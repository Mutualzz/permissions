export const spaceFlags = {
    // Identity flags
    Verified: 1n << 0n,
    Official: 1n << 1n,
    Archived: 1n << 2n,
    Locked: 1n << 3n,
    Nsfw: 1n << 4n,
} as const satisfies Record<string, bigint>;

export type SpaceFlag = keyof typeof spaceFlags;
export type SpaceFlags = typeof spaceFlags;
