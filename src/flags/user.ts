export const userFlags = {
    // Identities
    Staff: 1n << 0n,
    Verified: 1n << 1n,
    System: 1n << 2n,
    Disabled: 1n << 3n,
    Deleted: 1n << 4n,
    Founder: 1n << 5n,
    Tester: 1n << 6n,
    // 7–15 reserved for future identitys

    // For moderation
    // 16–29 reserved for moderation

    // Developer
    Employee: 1n << 30n,
    // 31–39 reserved for dev/internal use

    // Cosmetic
    EarlySupporter: 1n << 40n,

    BugHunter: 1n << 41n,
    CommunityHelper: 1n << 42n,
    // 44–59 reserved for cosmetic

    // Verification
    AgeConfirmed18Plus: 1n << 60n,
    // 60–63 reserved for future verification/compliance
} as const satisfies Record<string, bigint>;

export type UserFlag = keyof typeof userFlags;
export type UserFlags = typeof userFlags;
