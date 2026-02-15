// TODO: Currently empty, add flags as needed
export const channelFlags = {
    // Identity flags
    Placeholder: 1n << 0n,
} as const satisfies Record<string, bigint>;

export type ChannelFlag = keyof typeof channelFlags;
export type ChannelFlags = typeof channelFlags;
