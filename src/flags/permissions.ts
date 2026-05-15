// NOTE: Some bitfield are not fully implemented but i will put them in here
// So in the future I can implement them, some are not necessary yet
// *sigh* yes I know its like discord, but im still making it, cuz I like their permission system
export const permissionFlags = {
    // Space Management
    Administrator: 1n << 0n, // Allows most bitfield, bypasses channel overwrites
    ManageSpace: 1n << 1n, // Allows management and editing of spaces
    ManageChannels: 1n << 2n, // Allows management and editing of channels
    ManageRoles: 1n << 3n, // Allows managing roles
    ManageWebhooks: 1n << 4n, // Allows managing webhooks - TODO: Implement
    ManageExpressions: 1n << 5n, // Allows managing space expressions (emojis, stickers, sounds etc.) - TODO: Implement
    CreateExpressions: 1n << 6n, // Allows creating space expressions (emojis, stickers, sounds etc.) - TODO: Implement
    ViewAuditLog: 1n << 7n, // Allows viewing of audit logs - TODO: Implement
    ViewSpaceInsights: 1n << 8n, // Allows for viewing space insights - TODO: Implement

    // Member Management
    KickMembers: 1n << 9n, // Allows kicking members
    BanMembers: 1n << 10n, // Allows banning members
    ModerateMembers: 1n << 11n, // Allows moderating members (timeouts etc.) - TODO: Implement
    MuteMembers: 1n << 12n, // Allows muting members
    DeafenMembers: 1n << 13n, // Allows deafening members
    MoveMembers: 1n << 14n, // Allows moving members between voice channels - TODO: Implement
    ManageNicknames: 1n << 15n, // Allows managing nicknames of others - TODO: Implement
    CreateInvites: 1n << 16n, // Allows creation of invites

    // Text Channels
    ViewChannel: 1n << 17n, // Allows viewing a channel, includes reading text and joining voice
    SendMessages: 1n << 18n, // Allows sending messages in a channel
    ReadMessageHistory: 1n << 19n, // Allows reading message history
    ManageMessages: 1n << 20n, // Allows deleting other users' messages
    PinMessages: 1n << 21n, // Allows pinning messages - TODO: Implement
    EmbedLinks: 1n << 22n, // Links sent by users get auto embedded
    AttachFiles: 1n << 23n, // Allows sending images and files - TODO: Implement
    SendTTSMessages: 1n << 24n, // Allows sending text-to-speech messages - TODO: Implement
    SendVoiceMessages: 1n << 25n, // Allows sending voice messages - TODO: Implement
    SendPolls: 1n << 26n, // Allows sending polls - TODO: Implement
    BypassSlowmode: 1n << 27n, // Allows bypassing slowmode - TODO: Implement
    MentionEveryone: 1n << 28n, // Allows mentioning @everyone - TODO: Implement
    AddReactions: 1n << 29n, // Allows adding reactions to messages - TODO: Implement

    // Threads
    ManageThreads: 1n << 30n, // Allows managing threads - TODO: Implement
    CreatePublicThreads: 1n << 31n, // Allows creating public threads in a channel - TODO: Implement
    CreatePrivateThreads: 1n << 32n, // Allows creating private threads in a channel - TODO: Implement
    SendMessagesInThreads: 1n << 33n, // Allows sending messages in threads - TODO: Implement

    // External Content
    UseExternalEmojis: 1n << 34n, // Allows using emojis not associated with current space - TODO: Implement
    UseExternalStickers: 1n << 35n, // Allows using external stickers - TODO: Implement
    UseExternalSounds: 1n << 36n, // Allows using external sounds - TODO: Implement
    UseExternalApps: 1n << 37n, // Allows using external apps - TODO: Implement

    // Voice Channels
    Connect: 1n << 38n, // Allows joining voice channels
    Speak: 1n << 39n, // Allows speaking in a voice channel
    Stream: 1n << 40n, // Allows streaming in a voice channel - TODO: Implement
    UseVAD: 1n << 41n, // Allows using voice activity detection - TODO: Implement
    PrioritySpeaker: 1n << 42n, // Allows using priority speaker in a voice channel - TODO: Implement
    RequestToSpeak: 1n << 43n, // Allows requesting to speak in a voice channel - TODO: Implement
    UseSoundboard: 1n << 44n, // Allows using soundboard - TODO: Implement
    UseEmbeddedActivities: 1n << 45n, // Allows using embedded activities - TODO: Implement

    // Personal
    ChangeNickname: 1n << 46n, // Allows changing own nickname - TODO: Implement
    UseApplicationCommands: 1n << 47n, // Allows using application commands - TODO: Implement

    // Events
    ManageEvents: 1n << 48n, // Allows managing events - TODO: Implement
    CreateEvents: 1n << 49n, // Allows creating events - TODO: Implement
} as const satisfies Record<string, bigint>;

export type PermissionFlag = keyof typeof permissionFlags;
export type PermissionFlags = typeof permissionFlags;
