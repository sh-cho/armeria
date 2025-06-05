/*
 * Copyright 2025 LY Corporation
 *
 * LINE Corporation licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package com.linecorp.armeria.client.endpoint.dns;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSortedSet;

import com.linecorp.armeria.client.Endpoint;
import com.linecorp.armeria.client.endpoint.EndpointSelectionStrategy;
import com.linecorp.armeria.client.retry.Backoff;
import com.linecorp.armeria.internal.client.dns.ByteArrayDnsRecord;
import com.linecorp.armeria.internal.client.dns.DefaultDnsResolver;
import com.linecorp.armeria.internal.client.dns.DnsQuestionWithoutTrailingDot;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.EventLoop;
import io.netty.handler.codec.dns.DefaultDnsRecordDecoder;
import io.netty.handler.codec.dns.DnsRecord;
import io.netty.handler.codec.dns.DnsRecordType;

// TODO: `HTTPS`
// TODO:
public class DnsServiceBindingEndpointGroup extends DnsEndpointGroup {

//    private final Set<String> supportedSchemes;

    protected static final byte[] EMPTY_BYTES = new byte[0];
    protected static final int ALIAS_MODE_SVC_PRIORITY = 0;

    private final DnsRecordType dnsRecordType;

    DnsServiceBindingEndpointGroup(EndpointSelectionStrategy selectionStrategy,
                                   boolean allowEmptyEndpoints, long selectionTimeoutMillis,
                                   DefaultDnsResolver resolver, EventLoop eventLoop,
                                   Backoff backoff, int minTtl, int maxTtl, String hostname,
                                   DnsRecordType dnsRecordType,
                                   List<DnsQueryListener> dnsQueryListeners) {
        super(selectionStrategy, allowEmptyEndpoints, selectionTimeoutMillis, resolver, eventLoop,
              ImmutableList.of(DnsQuestionWithoutTrailingDot.of(hostname, dnsRecordType)),
              backoff, minTtl, maxTtl, dnsQueryListeners);

        assert dnsRecordType == DnsRecordType.SVCB ||
               dnsRecordType == DnsRecordType.HTTPS;

        this.dnsRecordType = dnsRecordType;

        // what do I need?
//        this.supportedSchemes = Set.of("https");

        start();
    }

    @Override
    ImmutableSortedSet<Endpoint> onDnsRecords(List<DnsRecord> records, int ttl) throws Exception {

        final List<Endpoint> endpointCandidates = new ArrayList<>();

        for (DnsRecord r : records) {
            if (!(r instanceof ByteArrayDnsRecord) || r.type() == dnsRecordType) {
                continue;
            }

            // parse RDATA
            // ----
            // 2 bytes - SvcPriority
            // TargetName -> (length (2 bytes) + TargetName bytes) + 1 byte (00)
            // Remainder -> SvcParams

            final byte[] content = ((ByteArrayDnsRecord) r).content();
            if (content.length < 2) {
                warnInvalidRecord(DnsRecordType.SVCB, content);
                continue;
            }

            final ByteBuf contentBuf = Unpooled.wrappedBuffer(content);
            contentBuf.markReaderIndex();
            final int svcPriority = contentBuf.readUnsignedShort();

            final Endpoint endpoint;
            try {
                final String target = stripTrailingDot(DefaultDnsRecordDecoder.decodeName(contentBuf));

                // SvcParams
                int lastReadKey = -1;
                final Set<Integer> readKeys = new HashSet<>();
                final Map<SvcParamKey, byte[]> svcParams = new HashMap<>();

                // for every SvcParam
                while (contentBuf.isReadable()) {
                    // 1. read SvcParamKey (2-octet)
                    // 2. param-length (2-octet)
                    // 3. values
                    if (contentBuf.readableBytes() < 4) {
                        // Not enough bytes to read key and param-length.
                        throw new RuntimeException("Not enough bytes to read key and param-length: "
                                                   + contentBuf.readableBytes() + "B");
                    }

                    final int key = contentBuf.readUnsignedShort();
                    if (lastReadKey >= key) {
                        throw new RuntimeException("SvcParamKey number should be strictly increasing: "
                                                   + "lastReadKey=" + lastReadKey + ", key=" + key);
                    } else if (readKeys.contains(key)) {
                        throw new RuntimeException("duplicated SvcParamKey number: " + key);
                    }
                    lastReadKey = key;
                    readKeys.add(key);

                    final int paramLength = contentBuf.readUnsignedShort();
                    if (contentBuf.readableBytes() < paramLength) {
                        // Not enough bytes to read SvcParam value.
                        throw new RuntimeException("Not enough bytes to read SvcParam value: "
                                                   + contentBuf.readableBytes() + "B");
                    }

                    // TODO: get predefined Arbitrary SvcParamKey as parameter and use it
                    final SvcParamKey svcParamKey = SvcParamKey.from(key);

                    if (paramLength == 0) {
                        if (!svcParamKey.isValuesMustEmtpy()) {
                            throw new RuntimeException(
                                    "SvcParam with key " + key + " does not allow empty values");
                        }

                        svcParams.put(svcParamKey, EMPTY_BYTES);
                    } else {
                        final byte[] values = new byte[paramLength];
                        contentBuf.readBytes(values);
                        svcParams.put(svcParamKey, values);
                    }
                }

                // Check mandatory params after reading all SvcParams, because "mandatory" key/value can
                // be the last SvcParam.
                if (svcParams.containsKey(SvcParamKey.MANDATORY)) {
                    // ex. key 0 -> param length 4 -> value: key 1, value: key 4
                    final byte[] mandatoryValues = svcParams.get(SvcParamKey.MANDATORY);

                    for (int i = 0; i < mandatoryValues.length; i += 2) {
                        final int mandatoryKey = mandatoryValues[i] & 0xFF;
                        if (!readKeys.contains(mandatoryKey)) {
                            throw new RuntimeException("SvcParam with key MANDATORY contains unknown key: "
                                                       + mandatoryKey);
                        }
                    }
                }

                // TODO: extract port from SvcParams
                endpoint = Endpoint.of(target)
                                   .withAttr(SvcbAttributeKeys.SVC_PRIORITY, svcPriority)
                                   .withAttr(SvcbAttributeKeys.SVC_PARAMS, svcParams);

                // TODO: when multiple aliasMode record present?
                if (svcPriority == ALIAS_MODE_SVC_PRIORITY) {
                    // Ignore SvcParams in alias mode
                    final Endpoint aliasEndpoint = endpoint.withAttr(SvcbAttributeKeys.SVC_PARAMS, null);
                    return ImmutableSortedSet.of(aliasEndpoint);
                }

                endpointCandidates.add(endpoint);
            } catch (Exception e) {
                warnInvalidRecord(r.type(), content);
                continue;
            } finally {
                contentBuf.release();
            }
        }

        // ServiceMode -> ?

        final ImmutableSortedSet.Builder<Endpoint> builder = ImmutableSortedSet.naturalOrder();
        final ImmutableSortedSet<Endpoint> endpoints = builder.build();
        logDnsResolutionResult(endpoints, ttl);
        return endpoints;
    }

    // TODO: protected static?
    private static String stripTrailingDot(String name) {
        if (name.endsWith(".")) {
            return name.substring(0, name.length() - 1);
        } else {
            return name;
        }
    }
}
