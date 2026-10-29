#include "defuser.h"

#include <inttypes.h>
#include <stdio.h>

#define MAX_FIELDS 8

/* Match the bomb's 32-bit rotates, including its masked shift counts.
 * Mask the complementary count too: count == 0 never shifts by 32. */
static uint32_t rotate_left_32(uint32_t value, unsigned count) {
    count &= 31U;
    return (value << count) | (value >> ((32U - count) & 31U));
}

static uint32_t rotate_right_32(uint32_t value, unsigned count) {
    count &= 31U;
    return (value >> count) | (value << ((32U - count) & 31U));
}

/* A general solver for this personal bomb, not a table of seed/answer pairs.
 * The unchanged driver derives each challenge and the Honor transcript context.
 * Every answer below is recomputed from those inputs. Only the bomb's fixed
 * instruction constants and read-only pointer tables are reconstructed here.
 *
 * Keep 64-bit shifts before truncation where the bomb uses a 64-bit register.
 * uint32_t arithmetic wraps modulo 2^32, just like its 32-bit instructions;
 * unsigned right shifts are logical, and no signed overflow is required.
 */
static int write_answer(char *out, size_t cap, const uint32_t *values, size_t count) {
    if (out == NULL || cap == 0 || count == 0 || count > MAX_FIELDS) return 1;
    size_t used = 0;
    for (size_t i = 0; i < count; ++i) {
        int size = snprintf(out + used, cap - used, "%s%" PRIu32, i ? " " : "", values[i]);
        if (size < 0 || (size_t)size >= cap - used) return 1;
        used += (size_t)size;
    }
    return 0;
}

int solve_phase_1(uint64_t challenge, char *out, size_t cap) {
    const uint32_t low = (uint32_t)challenge;
    const uint32_t high = (uint32_t)(challenge >> 32);
    const uint32_t middle = (uint32_t)(challenge >> 16);
    /* p1_step0(low, high), p1_step1(high, middle), p1_step2(second, low). */
    const uint32_t first = (low + UINT32_C(2) * high) ^ UINT32_C(0x611d);
    const uint32_t second = UINT32_C(8) * high + (middle ^ UINT32_C(0x5a93));
    const uint32_t values[] = {
        (UINT32_C(5) * second + low) ^ UINT32_C(0x33b3) ^ first
    };
    return write_answer(out, cap, values, 1);
}

int solve_phase_2(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[6];
    values[0] = (uint32_t)((challenge >> 35) & UINT64_C(31)) + UINT32_C(9);
    /* At 0x402108, the shift starts at 13 and increases by 4 per iteration.
     * The six-bit windows overlap: do not change the stride to six bits.
     */
    for (unsigned i = 1; i < 6; ++i) {
        const uint32_t part = (uint32_t)((challenge >> (9 + 4 * i)) & UINT64_C(63));
        values[i] = (UINT32_C(3) * values[i - 1]) ^ (part + i);
    }
    return write_answer(out, cap, values, 6);
}

int solve_phase_3(uint64_t challenge, char *out, size_t cap) {
    const uint32_t selector = (uint32_t)(challenge & UINT64_C(7));
    const uint32_t x = (uint32_t)(challenge >> 3) ^ (uint32_t)(challenge >> 32);
    uint32_t result;
    /* The jump table at 0x4057e0 maps selectors to cases 5,3,1,4,6,0,7,2. */
    switch (selector) {
        case 0: result = (UINT32_C(2) * x) ^ UINT32_C(0x839); break;
        case 1: result = (x ^ UINT32_C(0x2cba)) + (x >> 1); break;
        case 2: result = UINT32_C(5) * x + UINT32_C(0x304a3); break;
        case 3: result = (x ^ UINT32_C(0x7fc7)) + (x >> 2); break;
        case 4: result = UINT32_C(5) * x + UINT32_C(0x4d92); break;
        case 5: result = (UINT32_C(4) * x) ^ UINT32_C(0xbaff); break;
        case 6: result = UINT32_C(5) * x + UINT32_C(0x29a04); break;
        case 7: result = UINT32_C(3) * x + UINT32_C(0x7ee0); break;
        default: return 1; /* Unreachable: selector is masked to 0..7. */
    }
    const uint32_t values[] = {selector, result};
    return write_answer(out, cap, values, 2);
}

static uint32_t phase4_walk(uint32_t target, uint32_t low, uint32_t high,
                            uint32_t bias) {
    /* Invariant: low <= target <= high <= 127. Each recursive interval
     * shrinks; equality stops before either endpoint can underflow/overflow.
     * There are at most eight calls, including the initial call.
     */
    const uint32_t middle = low + ((high - low) >> 1);
    if (target == middle) return (middle + UINT32_C(7)) ^ bias;
    if (target < middle) {
        const uint32_t child = phase4_walk(target, low, middle - 1, bias);
        return (UINT32_C(3) * child) ^ (middle + bias) ^ UINT32_C(11);
    }
    const uint32_t child = phase4_walk(target, middle + 1, high, bias);
    return (UINT32_C(3) * child) ^ (middle + bias) ^ UINT32_C(2);
}

int solve_phase_4(uint64_t challenge, char *out, size_t cap) {
    const uint32_t target = (uint32_t)(challenge & UINT64_C(127));
    const uint32_t bias = (uint32_t)(challenge >> 7) ^ (uint32_t)(challenge >> 32);
    const uint32_t values[] = {phase4_walk(target, 0, 127, bias)};
    return write_answer(out, cap, values, 1);
}

struct phase5_node {
    const struct phase5_node *next;
    uint32_t tag;
    uint32_t bias;
};

/* Reconstructed constant data from p5_nodes (0x405b60), in address order.
 * The original offsets are next=0, tag=8, bias=12, with a 16-byte stride.
 * These are the personal bomb's fixed data, never a seed/answer lookup table.
 */
static const struct phase5_node phase5_nodes[12] = {
    {&phase5_nodes[1],  UINT32_C(0xb53), UINT32_C(0xd0ef)},
    {&phase5_nodes[11], UINT32_C(0x552), UINT32_C(0x4148)},
    {&phase5_nodes[0],  UINT32_C(0x01b), UINT32_C(0x45ce)},
    {&phase5_nodes[6],  UINT32_C(0x168), UINT32_C(0xde8e)},
    {&phase5_nodes[2],  UINT32_C(0x90f), UINT32_C(0x59be)},
    {&phase5_nodes[8],  UINT32_C(0x64f), UINT32_C(0x4061)},
    {&phase5_nodes[5],  UINT32_C(0x775), UINT32_C(0x716f)},
    {&phase5_nodes[9],  UINT32_C(0x367), UINT32_C(0xae83)},
    {&phase5_nodes[10], UINT32_C(0x83d), UINT32_C(0x8554)},
    {NULL,             UINT32_C(0x23c), UINT32_C(0x4651)},
    {&phase5_nodes[4],  UINT32_C(0xa51), UINT32_C(0x50dd)},
    {&phase5_nodes[7],  UINT32_C(0x461), UINT32_C(0xce89)}
};

int solve_phase_5(uint64_t challenge, char *out, size_t cap) {
    /* Every permitted head has at least four reachable nodes. visits is
     * always 1..4, so each dereferenced node is valid for every challenge.
     * The answer uses the last visited tag, not the following node's tag.
     */
    static const unsigned heads[8] = {3, 6, 5, 8, 10, 4, 2, 0};
    const unsigned visits = 1 + (unsigned)((challenge >> 3) & UINT64_C(3));
    const struct phase5_node *node = &phase5_nodes[heads[challenge & UINT64_C(7)]];
    uint32_t accumulator = (uint32_t)(challenge >> 6) ^
                           (uint32_t)(challenge >> 32) ^ UINT32_C(0xa072);
    uint32_t last_tag = 0;
    for (unsigned i = 0; i < visits; ++i) {
        accumulator = (UINT32_C(3) * accumulator + node->bias) ^ node->tag;
        last_tag = node->tag;
        node = node->next;
    }
    const uint32_t values[] = {accumulator, last_tag};
    return write_answer(out, cap, values, 2);
}

static uint32_t phase6_op_0(uint32_t x) {
    return rotate_left_32(x, 2U) ^ UINT32_C(0x42fd);
}

static uint32_t phase6_op_1(uint32_t x) {
    return (x ^ UINT32_C(0x22ab)) + UINT32_C(2) * x;
}

static uint32_t phase6_op_2(uint32_t x) {
    return (x + UINT32_C(0x98fb)) ^ (x >> 3);
}

static uint32_t phase6_op_3(uint32_t x) {
    return (UINT32_C(4) * x + UINT32_C(0xfa0c)) ^ (UINT32_C(3) * x);
}

static uint32_t phase6_op_4(uint32_t x) {
    return rotate_right_32(x, 5U);
}

static uint32_t phase6_op_5(uint32_t x) {
    return ((x >> 3) ^ x) + UINT32_C(0xa74b);
}

int solve_phase_6(uint64_t challenge, char *out, size_t cap) {
    /* Preserve the pointer table's repeated entries and exact index order.
     * Both indices range over 0..7 independently (all 64 pairs are legal).
     */
    static uint32_t (*const ops[8])(uint32_t) = {
        phase6_op_1, phase6_op_5, phase6_op_2, phase6_op_4,
        phase6_op_1, phase6_op_3, phase6_op_0, phase6_op_4
    };
    const unsigned first = (unsigned)(challenge & UINT64_C(7));
    const unsigned second = (unsigned)((challenge >> 3) & UINT64_C(7));
    const uint32_t x = (uint32_t)(challenge >> 6) ^ (uint32_t)(challenge >> 32);
    const uint32_t intermediate = ops[first](x) ^ UINT32_C(0x3af3);
    const uint32_t values[] = {ops[second](intermediate) + UINT32_C(0x1950)};
    return write_answer(out, cap, values, 1);
}

int solve_secret(uint64_t challenge, uint64_t context, char *out, size_t cap) {
    if (out == NULL || cap == 0) return 1;
    const uint32_t selector = (uint32_t)(context & UINT64_C(3));
    const uint32_t folded_challenge = (uint32_t)challenge ^ (uint32_t)(challenge >> 32);
    const uint32_t folded_context = (uint32_t)context ^ (uint32_t)(context >> 32);
    const uint32_t x = folded_challenge ^ folded_context;
    const uint32_t mixed = ((x >> 3) ^ UINT32_C(0x3445)) + (x ^ UINT32_C(0x17ba));
    const uint32_t second = mixed ^ (selector * UINT32_C(0x17ba)) ^
                            (uint32_t)(context >> 16);
    const uint32_t third = second ^ (folded_context + selector + UINT32_C(0x3445) +
                                     (folded_challenge >> 3));
    /* secret_copy fills an object: scratch[32], marker[4], then answer.
     * Little-endian 0x4e45504f is "OPEN". The three decimal fields begin
     * immediately at byte 36; the context is supplied by the real six-line
     * transcript, never inferred from a fixed seed. At most 59 characters
     * plus the terminator are written, within the driver's ANSWER_CAP.
     */
    const int size = snprintf(out, cap,
                             "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOPEN%" PRIu32
                             " %" PRIu32 " %" PRIu32, selector, second, third);
    return size < 0 || (size_t)size >= cap;
}
