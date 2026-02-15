export const memberFlags = {
    // Identity flags
    Owner: 1n << 0n,
};

export type MemberFlag = keyof typeof memberFlags;
export type MemberFlags = typeof memberFlags;
