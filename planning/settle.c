// Settlement planner experiment: greedy vs. exact minimum number of transfers.
// Build: gcc -O2 -o settle settle.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

static uint64_t rs = 0x9E3779B97F4A7C15ULL;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
static long uni(long lo, long hi) { return lo + (long)(rnd() % (uint64_t)(hi - lo + 1)); }

// Greedy: match the largest creditor with the largest debtor (ties by index).
static int greedy(const long *b0, int n) {
  long b[64]; memcpy(b, b0, n * sizeof(long));
  int cnt = 0;
  for (;;) {
    int c = -1, d = -1;
    for (int i = 0; i < n; i++) {
      if (b[i] > 0 && (c < 0 || b[i] > b[c])) c = i;
      if (b[i] < 0 && (d < 0 || b[i] < b[d])) d = i;
    }
    if (c < 0 || d < 0) break;
    long t = b[c] < -b[d] ? b[c] : -b[d];
    b[c] -= t; b[d] += t; cnt++;
  }
  return cnt;
}

// Exact: OPT = m - s*, s* = max number of zero-sum blocks. O(2^m * m).
static uint8_t *dp; static long *sm;
static int exact(const long *b0, int n, int *mout) {
  long v[64]; int m = 0;
  for (int i = 0; i < n; i++) if (b0[i]) v[m++] = b0[i];
  *mout = m;
  if (m == 0) return 0;
  uint32_t full = (1u << m) - 1;
  dp[0] = 0; sm[0] = 0;
  for (uint32_t S = 1; S <= full; S++) {
    int low = __builtin_ctz(S);
    sm[S] = sm[S & (S - 1)] + v[low];
    uint8_t best = 0;
    for (uint32_t T = S; T; T &= T - 1) {
      uint8_t x = dp[S & ~(T & -T)];
      if (x > best) best = x;
    }
    dp[S] = best + (sm[S] == 0);
  }
  return m - dp[full];
}

// Workload generator: E expenses among n members.
//  mode 0 (heterogeneous): amounts in [1.00, 200.00], split among a random subset.
//  mode 1 (recurring): amounts from {10,20,50,100}.00, split equally among all.
static void workload(long *b, int n, int E, int mode) {
  memset(b, 0, n * sizeof(long));
  for (int e = 0; e < E; e++) {
    int k = (int)uni(0, n - 1);
    long a; int part[64], p = 0;
    if (mode == 0) {
      a = uni(100, 20000);
      for (int i = 0; i < n; i++) if (rnd() % 10 < 7) part[p++] = i;
      if (p == 0) part[p++] = k;
    } else {
      static const long A[4] = {1000, 2000, 5000, 10000};
      a = A[rnd() % 4];
      for (int i = 0; i < n; i++) part[p++] = i;
    }
    long q = a / p, r = a % p;
    b[k] += a;
    for (int i = 0; i < p; i++) b[part[i]] -= q + (i < r ? 1 : 0);
  }
}

int main(void) {
  dp = malloc((size_t)1 << 26); sm = malloc(sizeof(long) * ((size_t)1 << 26));
  int ns[] = {5, 10, 15, 20};
  printf("mode n trials mean_m mean_greedy mean_opt frac_opt max_ratio mean_ms_exact\n");
  for (int mode = 0; mode < 2; mode++)
    for (int ni = 0; ni < 4; ni++) {
      int n = ns[ni], trials = 1000;
      double sm_m = 0, sg = 0, so = 0, st = 0, maxr = 1; int eq = 0, cnt = 0;
      for (int t = 0; t < trials; t++) {
        long b[64]; workload(b, n, 5 * n, mode);
        int m; clock_t c0 = clock();
        int o = exact(b, n, &m);
        st += (double)(clock() - c0) / CLOCKS_PER_SEC * 1000;
        int g = greedy(b, n);
        if (o == 0) continue;
        cnt++; sm_m += m; sg += g; so += o; if (g == o) eq++;
        if ((double)g / o > maxr) maxr = (double)g / o;
      }
      printf("%d %d %d %.2f %.2f %.2f %.3f %.3f %.3f\n", mode, n, cnt, sm_m / cnt,
             sg / cnt, so / cnt, (double)eq / cnt, maxr, st / trials);
    }
  // Scaling of the exact DP with m.
  printf("m ms_exact\n");
  for (int m = 16; m <= 26; m += 2) {
    long b[64]; long s = 0;
    for (int i = 0; i < m - 1; i++) { b[i] = uni(-20000, 20000); if (!b[i]) b[i] = 1; s += b[i]; }
    b[m - 1] = -s; if (!b[m - 1]) { b[0] += 1; b[m - 1] = -1; }
    int mm; clock_t c0 = clock(); exact(b, m, &mm);
    printf("%d %.1f\n", mm, (double)(clock() - c0) / CLOCKS_PER_SEC * 1000);
  }
  return 0;
}
