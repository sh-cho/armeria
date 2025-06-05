package com.linecorp.armeria.client.endpoint.dns;

import java.util.Map;

import io.netty.util.AttributeKey;

final class SvcbAttributeKeys {

    static final AttributeKey<Integer> SVC_PRIORITY =
            AttributeKey.valueOf(SvcbAttributeKeys.class, "SVC_PRIORITY");

    static final AttributeKey<Map<SvcParamKey, byte[]>> SVC_PARAMS =
            AttributeKey.valueOf(SvcbAttributeKeys.class, "SVC_PARAMS");

    private SvcbAttributeKeys() {}
}
