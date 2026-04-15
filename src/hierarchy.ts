import { permissionFlags } from "./flags";

export type RoleLike = { id: string; position: number };
export type MemberLike = { userId: string; roleIds: string[] };

export function isOwner(spaceOwnerId: string, actorUserId: string) {
    return spaceOwnerId === actorUserId;
}

export function isAdmin(bits: bigint) {
    return (
        (bits & permissionFlags.Administrator) === permissionFlags.Administrator
    );
}

export function topRolePos(
    roleIds: string[],
    rolesById: Map<string, RoleLike>,
): number {
    let top = -1;
    for (const id of roleIds) {
        const r = rolesById.get(id);
        if (r) top = Math.max(top, r.position ?? -1);
    }
    return top;
}

export function canManageRoles(opts: {
    spaceOwnerId: string;
    actorUserId: string;
    actorBits: bigint;
    actorHasManageRoles: boolean;
}) {
    const { spaceOwnerId, actorUserId, actorBits, actorHasManageRoles } = opts;

    if (isOwner(spaceOwnerId, actorUserId)) return true;

    // Admin bypasses permission gating
    if (isAdmin(actorBits)) return true;

    return actorHasManageRoles;
}

export function canEditRole(opts: {
    spaceOwnerId: string;
    actorUserId: string;
    actorBits: bigint;
    actorHasManageRoles: boolean;
    actorTopPos: number;
    rolePos: number;
    isEveryone: boolean;
    action: "view" | "edit" | "delete";
}) {
    const {
        spaceOwnerId,
        actorUserId,
        actorBits,
        actorHasManageRoles,
        actorTopPos,
        rolePos,
        isEveryone,
        action,
    } = opts;

    // delete @everyone never allowed
    if (action === "delete" && isEveryone) return false;

    if (isOwner(spaceOwnerId, actorUserId)) return true;

    // must pass permission gate
    const gate = canManageRoles({
        spaceOwnerId,
        actorUserId,
        actorBits,
        actorHasManageRoles,
    });
    if (!gate) return false;

    // must be strictly higher
    return actorTopPos > rolePos;
}

export function canAssignRole(opts: {
    spaceOwnerId: string;
    actorUserId: string;
    actorBits: bigint;
    actorHasManageRoles: boolean;
    actorTopPos: number;

    targetTopPos: number;

    rolePos: number;
    isEveryone: boolean;
}) {
    const {
        spaceOwnerId,
        actorUserId,
        actorBits,
        actorHasManageRoles,
        actorTopPos,
        targetTopPos,
        rolePos,
        isEveryone,
    } = opts;

    // never assign/remove @everyone explicitly
    if (isEveryone) return false;

    if (isOwner(spaceOwnerId, actorUserId)) return true;

    const gate = canManageRoles({
        spaceOwnerId,
        actorUserId,
        actorBits,
        actorHasManageRoles,
    });
    if (!gate) return false;

    // cannot touch members at/above you
    if (!(actorTopPos > targetTopPos)) return false;

    // cannot assign/remove roles at/above you
    return actorTopPos > rolePos;
}
