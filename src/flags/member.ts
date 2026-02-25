export const memberFlags = {
    // Identity flags
    Owner: 1n << 0n,

    // Moderation flags
    VoiceSpaceMuted: 1n << 1n,
    VoiceSpaceDeafened: 1n << 2n,
};

export type MemberFlag = keyof typeof memberFlags;
export type MemberFlags = typeof memberFlags;
