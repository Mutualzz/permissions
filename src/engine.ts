import type { OverwriteLike, RoleLike, Snowflake } from "./types";

export function toBigInt(v: bigint | string): bigint {
    return typeof v === "bigint" ? v : BigInt(v);
}

export const ALL_BITS = BigInt("0xffffffffffffffff");

export function resolveBaseBits(
    spaceId: Snowflake,
    roles: RoleLike[],
    memberRoleIds: Snowflake[],
): bigint {
    const rolesById = new Map<string, bigint>();
    for (const role of roles)
        rolesById.set(role.id, toBigInt(role.permissions));

    let bits = 0n;

    // @everyone == spaceId
    const everyone = rolesById.get(spaceId);
    if (everyone != null) bits |= everyone;

    for (const roleId of memberRoleIds) {
        const permission = rolesById.get(roleId);
        if (permission != null) bits |= permission;
    }

    return bits;
}

export function applyOverwriteLayer(
    baseBits: bigint,
    overwrites: OverwriteLike[] | null | undefined,
    everyoneRoleId: Snowflake,
    memberRoleIds: Snowflake[],
    userId: Snowflake,
): bigint {
    if (!overwrites?.length) return baseBits;

    let bits = baseBits;

    const apply = (allow: bigint, deny: bigint) => {
        bits &= ~deny;
        bits |= allow;
    };

    // everyone
    const everyoneOw = overwrites.find((o) => o.roleId === everyoneRoleId);
    if (everyoneOw)
        apply(toBigInt(everyoneOw.allow), toBigInt(everyoneOw.deny));

    // roles (aggregate)
    const memberSet = new Set(memberRoleIds);
    let roleAllow = 0n;
    let roleDeny = 0n;

    for (const ow of overwrites) {
        if (!ow.roleId) continue;
        if (!memberSet.has(ow.roleId)) continue;
        roleAllow |= toBigInt(ow.allow);
        roleDeny |= toBigInt(ow.deny);
    }
    apply(roleAllow, roleDeny);

    // 3) member
    const memberOw = overwrites.find((ow) => ow.userId === userId);
    if (memberOw) apply(toBigInt(memberOw.allow), toBigInt(memberOw.deny));

    return bits;
}

export function resolveEffectiveChannelBits(opts: {
    baseBits: bigint;
    userId: Snowflake;
    everyoneRoleId: Snowflake;
    memberRoleIds: Snowflake[];
    parentOverwrites?: OverwriteLike[] | null;
    channelOverwrites?: OverwriteLike[] | null;
}): bigint {
    const {
        baseBits,
        userId,
        everyoneRoleId,
        memberRoleIds,
        parentOverwrites,
        channelOverwrites,
    } = opts;

    let bits = baseBits;
    bits = applyOverwriteLayer(
        bits,
        parentOverwrites,
        everyoneRoleId,
        memberRoleIds,
        userId,
    );
    bits = applyOverwriteLayer(
        bits,
        channelOverwrites,
        everyoneRoleId,
        memberRoleIds,
        userId,
    );
    return bits;
}

export function hasAll(bits: bigint, required: bigint): boolean {
    return (bits & required) === required;
}

export function hasAny(bits: bigint, required: bigint): boolean {
    return (bits & required) !== 0n;
}
