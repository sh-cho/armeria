package com.linecorp.armeria.client.endpoint.dns;

import java.util.HashMap;
import java.util.Map;

import com.google.common.base.MoreObjects;

import com.linecorp.armeria.common.annotation.Nullable;

public final class SvcParamKey {

    public static final SvcParamKey MANDATORY = new SvcParamKey(Type.MANDATORY, 0, false);
    public static final SvcParamKey ALPN = new SvcParamKey(Type.ALPN, 1, false);
    public static final SvcParamKey NO_DEFAULT_ALPN = new SvcParamKey(Type.NO_DEFAULT_ALPN, 2, true);
    public static final SvcParamKey PORT = new SvcParamKey(Type.PORT, 3, false);
    public static final SvcParamKey IPV4_HINT = new SvcParamKey(Type.IPV4_HINT, 4, false);
    public static final SvcParamKey ECH = new SvcParamKey(Type.ECH, 5, false);
    public static final SvcParamKey IPV6_HINT = new SvcParamKey(Type.IPV6_HINT, 6, false);
    public static final SvcParamKey DOHPATH = new SvcParamKey(Type.DOHPATH, 7, false);
    public static final SvcParamKey OHTTP = new SvcParamKey(Type.OHTTP, 8, true);
    public static final SvcParamKey TCP_SUPPORTED_GROUPS = new SvcParamKey(Type.TCP_SUPPORTED_GROUPS, 9, false);
    public static final SvcParamKey KEY_INVALID = new SvcParamKey(Type.KEY_INVALID, 65535, false);

    private static final Map<Integer, SvcParamKey> INITIAL_SVC_PARAM_KEY_MAP = new HashMap<>();

    static {
        for (SvcParamKey key : new SvcParamKey[] {
                MANDATORY, ALPN, NO_DEFAULT_ALPN, PORT,
                IPV4_HINT, ECH, IPV6_HINT, DOHPATH,
                OHTTP, TCP_SUPPORTED_GROUPS, KEY_INVALID
        }) {
            INITIAL_SVC_PARAM_KEY_MAP.put(key.number, key);
        }
    }

    enum Type {
        MANDATORY,
        ALPN,
        NO_DEFAULT_ALPN,
        PORT,
        IPV4_HINT,
        ECH,
        IPV6_HINT,
        DOHPATH,
        OHTTP,
        TCP_SUPPORTED_GROUPS,
        /**
         * 65535
         */
        KEY_INVALID,
        /**
         * 65280-65534
         */
        KEY_PRIVATE,
        KEY_ARBITRARY,
    }

    private final Type type;
    private final int number;
    private final boolean valuesMustEmtpy;

    private SvcParamKey(Type type, int number, boolean valuesMustEmtpy) {
        this.type = type;
        this.number = number;
        this.valuesMustEmtpy = valuesMustEmtpy;
    }

    public static SvcParamKey from(int number) {
        return from(number, false);
    }

    public static SvcParamKey from(int number, boolean valuesMustEmtpy) {
        if (INITIAL_SVC_PARAM_KEY_MAP.containsKey(number)) {
            return INITIAL_SVC_PARAM_KEY_MAP.get(number);
        } else if (65280 <= number && number <= 65534) {
            return new SvcParamKey(Type.KEY_PRIVATE, number, valuesMustEmtpy);
        } else {
            return new SvcParamKey(Type.KEY_ARBITRARY, number, valuesMustEmtpy);
        }
    }

    @Nullable
    public static SvcParamKey find(int number) {
        return INITIAL_SVC_PARAM_KEY_MAP.get(number);
    }

    Type getType() {
        return type;
    }

    public int getNumber() {
        return number;
    }

    public boolean isValuesMustEmtpy() {
        return valuesMustEmtpy;
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                          .add("type", type)
                          .add("number", number)
                          .add("valuesMustEmtpy", valuesMustEmtpy)
                          .toString();
    }
}
