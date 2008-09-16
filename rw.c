#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>

#include <gmp.h>

static void
print(const char *banner, mpz_t n) {
  fprintf(stderr, "%s", banner);
  mpz_out_str(stderr, 16, n);
  fprintf(stderr, "\n");
}

static uint64_t
time_now() {
  struct timeval tv;

  gettimeofday(&tv, NULL);
  uint64_t r = tv.tv_sec;
  r *= 1000000;
  r += tv.tv_usec;

  return r;
}

// -----------------------------------------------------------------------------
// Generate a random prime number and store the result in @n.
//
// urfd: a file descriptor opened to a random source
// size: the (approx) size in bits for the resulting prime
// mod8: the prime, mod 8, shall be equal to this
// -----------------------------------------------------------------------------
static void
init_random_prime(mpz_t n, int urfd, unsigned size, unsigned mod8) {
  uint8_t buffer[2048];
  const unsigned bytes = size >> 3;

  if (bytes > sizeof(buffer))
    abort();

  mpz_init2(n, bytes);

  for (;;) {
    ssize_t r;

    do {
      r = read(urfd, buffer, bytes);
    } while (r == -1 && errno == EINTR);

    if (r != bytes)
      abort();

    mpz_import(n, bytes, 1, 1, 0, 0, buffer);
    mpz_setbit(n, 0);

    if (mod8 & 2) {
      mpz_setbit(n, 1);
    } else {
      mpz_clrbit(n, 1);
    }

    if (mod8 & 4) {
      mpz_setbit(n, 2);
    } else {
      mpz_clrbit(n, 2);
    }

    if (mpz_probab_prime_p(n, 10))
      break;
  }
}

// -----------------------------------------------------------------------------
// Generate a random element, storing the result in @e
//
// urfd: a file descriptor opened to a random source
// size: the (approx) size of the element in bits
// n: the result is reduced modulo this
// -----------------------------------------------------------------------------
static void
random_element(mpz_t e, int urfd, unsigned size, mpz_t n) {
  uint8_t buffer[2048];
  const unsigned bytes = size >> 3;

  if (bytes > sizeof(buffer))
    abort();

  mpz_init2(e, bytes);

  ssize_t r;

  do {
    r = read(urfd, buffer, bytes);
  } while (r == -1 && errno == EINTR);

  if (r != bytes)
    abort();

  mpz_import(e, bytes, 1, 1, 0, 0, buffer);
  mpz_mod(e, e, n);
}

// -----------------------------------------------------------------------------
// Return non-zero iff e is a quadratic residue mod p
// -----------------------------------------------------------------------------
static int
is_quadratic_residue(mpz_t e, mpz_t p) {
  mpz_t power, emod;

  mpz_init(emod);
  mpz_mod(emod, e, p);

  mpz_init_set(power, p);
  mpz_add_ui(power, power, 1);
  mpz_cdiv_q_2exp(power, power, 2);

  mpz_t r;
  mpz_init(r);

  mpz_powm(r, e, power, p);
  mpz_mul(r, r, r);
  mpz_mod(r, r, p);

  const int result = 0 == mpz_cmp(r, emod);
  mpz_clear(r);
  mpz_clear(power);
  mpz_clear(emod);

  return result;
}

// -----------------------------------------------------------------------------
// Calculate and return (u, v) such that uq + vq == 1
// -----------------------------------------------------------------------------
static void
xgcd(mpz_t u, mpz_t v, mpz_t ip, mpz_t iq) {
  mpz_t p, q;
  mpz_init_set(p, ip);
  mpz_init_set(q, iq);

  mpz_init_set_ui(u, 1);
  mpz_init_set_ui(v, 0);

  mpz_t x, y;
  mpz_init_set_ui(x, 0);
  mpz_init_set_ui(y, 1);

  mpz_t s, t;
  mpz_init(s);
  mpz_init(t);

  while (mpz_sgn(q)) {
    mpz_set(t, q);
    mpz_fdiv_qr(s, q, p, q);
    mpz_set(p, t);

    mpz_set(t, x);
    mpz_mul(x, s, x);
    mpz_sub(x, u, x);
    mpz_set(u, t);

    mpz_set(t, y);
    mpz_mul(y, s, y);
    mpz_sub(y, v, y);
    mpz_set(v, t);
  }

  mpz_clear(p);
  mpz_clear(q);
  mpz_clear(x);
  mpz_clear(y);
  mpz_clear(s);
  mpz_clear(t);
}

int
main() {
  const int urfd = open("/dev/urandom", O_RDONLY);

  mpz_t p, q, n;

  fprintf(stderr, "Generating group...\n");
  init_random_prime(p, urfd, 512, 3);
  init_random_prime(q, urfd, 512, 7);

  print("  p:", p);
  print("  q:", q);

  mpz_init(n);
  mpz_mul(n, p, q);

  print("  n:", n);

  fprintf(stderr, "Performing extended Euclid...\n");
  mpz_t u, v;
  xgcd(u, v, p, q);
  mpz_mul(u, u, p);
  mpz_mul(v, v, q);

  print ("  u:", u);
  print ("  v:", v);

  fprintf(stderr, "Picking random element...\n");
  mpz_t e;
  random_element(e, urfd, 1024, n);
  print("  e:", e);

  fprintf(stderr, "Tweaking...\n");

  int a = is_quadratic_residue(e, p);
  int b = is_quadratic_residue(e, q);

  fprintf(stderr, "  residue state: [%d, %d]\n", a, b);

  int mul_2 = 0, negate = 0;

  if (a ^ b) {
    mul_2 = 1;
    a ^= 1;
  }

  if (!a) {
    negate = 1;
    a ^= 1;
    b ^= 1;
  }

  fprintf(stderr, "  tweaks: 2:%d -:%d\n", mul_2, negate);
  if (negate) {
    mpz_neg(e, e);
  }
  if (mul_2) {
    mpz_mul_ui(e, e, 2);
  }
  if (negate || mul_2)
    mpz_mod(e, e, n);

  print("  tweaked e:", e);

  uint8_t root;
  read(urfd, &root, 1);
  root &= 3;

  fprintf(stderr, "Calculating root %d...\n", root);

  mpz_t pp1over4, qp1over4;

  mpz_init_set(pp1over4, p);
  mpz_add_ui(pp1over4, pp1over4, 1);
  mpz_cdiv_q_2exp(pp1over4, pp1over4, 2);

  mpz_init_set(qp1over4, q);
  mpz_add_ui(qp1over4, qp1over4, 1);
  mpz_cdiv_q_2exp(qp1over4, qp1over4, 2);

  mpz_t proot, qroot;

  mpz_init_set(proot, e);
  mpz_powm(proot, e, pp1over4, p);

  mpz_init_set(qroot, e);
  mpz_powm(qroot, e, qp1over4, q);

  if (root & 1)
    mpz_neg(proot, proot);
  if (root & 2)
    mpz_neg(qroot, qroot);

  mpz_mul(proot, proot, v);
  mpz_mul(qroot, qroot, u);
  mpz_add(proot, proot, qroot);
  mpz_mod(proot, proot, n);

  print("  sig:", proot);

  fprintf(stderr, "Performing 1000000 verifications\n");

  const uint64_t start_time = time_now();
  unsigned i;
  mpz_t temp;
  mpz_init(temp);
  for (i = 0; i < 1000000; ++i) {
    mpz_mul(temp, proot, proot);
    mpz_mod(temp, temp, n);

    if (mpz_cmp(temp, e))
      abort();
  }
  const uint64_t end_time = time_now();
  fprintf(stderr, "verify time: %f\n", ((double) (end_time - start_time)) / 1000000);

  return 0;
}
