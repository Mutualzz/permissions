export const roleFlags = {
    Everyone: 1n << 0n,
} as const satisfies Record<string, bigint>;

export type RoleFlag = keyof typeof roleFlags;
export type RoleFlags = typeof roleFlags;
