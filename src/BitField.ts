export class BitField<
    T extends Record<string, bigint>,
    K extends keyof T = keyof T,
> {
    bits: bigint;
    private readonly flags: Readonly<T>;

    private constructor(flags: Readonly<T>, bits: bigint = 0n) {
        this.flags = flags;
        this.bits = bits;
    }

    has(key: K) {
        const f = this.flags[key];
        return (this.bits & f) === f;
    }

    hasAny(...keys: K[]): boolean {
        const mask = this.mask(...keys);
        return (this.bits & mask) !== 0n;
    }

    hasAll(...keys: K[]): boolean {
        const mask = this.mask(...keys);
        return (this.bits & mask) === mask;
    }

    add(...keys: K[]): this {
        for (const k of keys) this.bits |= this.flags[k];
        return this;
    }

    remove(...keys: K[]): this {
        for (const k of keys) this.bits &= ~BigInt.asIntN(64, this.flags[k]);
        return this;
    }

    toggle(...keys: K[]): this {
        for (const k of keys) this.bits ^= this.flags[k];
        return this;
    }

    set(key: K, on: boolean): this {
        return on ? this.add(key) : this.remove(key);
    }

    clear(): this {
        this.bits = 0n;
        return this;
    }

    mask(...keys: K[]): bigint {
        let m = 0n;
        for (const k of keys) m |= this.flags[k];
        return m;
    }

    toArray(): K[] {
        const out: K[] = [];
        for (const k in this.flags) {
            // eslint-disable-next-line no-prototype-builtins
            if (Object.prototype.hasOwnProperty.call(this.flags, k)) {
                const key = k as unknown as K;
                if (this.has(key)) out.push(key);
            }
        }
        return out;
    }

    fromArray(keys: K[]): this {
        this.bits = 0n;
        return this.add(...keys);
    }

    toString(): string {
        return this.bits.toString();
    }

    toJSON(): string {
        return this.toString();
    }

    clone(): BitField<T, K> {
        return new BitField(this.flags, this.bits);
    }

    static fromString<T extends Record<string, bigint>, K extends keyof T>(
        flags: Readonly<T>,
        s: string,
    ) {
        return new BitField<T, K>(flags, BigInt(s));
    }

    static fromBits<T extends Record<string, bigint>, K extends keyof T>(
        flags: Readonly<T>,
        bits: bigint,
    ) {
        return new BitField<T, K>(flags, bits);
    }
}
