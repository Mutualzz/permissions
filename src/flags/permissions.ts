export const permissionFlags = {
    // Channels
    ViewChannel: 1n << 0n,
    ManageChannels: 1n << 1n,

    // Messages
    SendMessages: 1n << 2n,
    ManageMessages: 1n << 3n,

    // Roles
    ManageRoles: 1n << 4n,

    // Members
    KickMembers: 1n << 5n,
    BanMembers: 1n << 6n,

    // Invites
    CreateInvites: 1n << 7n,
    ManageInvites: 1n << 8n,

    // Space
    ManageSpace: 1n << 9n,

    Administrator: 1n << 60n,
} as const satisfies Record<string, bigint>;

export type PermissionFlag = keyof typeof permissionFlags;
export type PermissionFlags = typeof permissionFlags;
