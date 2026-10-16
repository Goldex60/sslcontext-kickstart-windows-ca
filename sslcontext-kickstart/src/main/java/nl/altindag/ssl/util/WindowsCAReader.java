/*
 * Copyright 2019 Thunderberry.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package nl.altindag.ssl.util;

import com.sun.jna.Native;
import com.sun.jna.platform.win32.Crypt32;
import com.sun.jna.platform.win32.WinCrypt;
import com.sun.jna.platform.win32.WTypes;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public final class WindowsCAReader {

    private WindowsCAReader() {
    }

    public static List<X509Certificate> loadCertificates()
            throws Exception {

        List<X509Certificate> certificates = new ArrayList<>();

        certificates.addAll(readStore(
                WinCrypt.CERT_SYSTEM_STORE_CURRENT_USER));

        certificates.addAll(readStore(
                WinCrypt.CERT_SYSTEM_STORE_LOCAL_MACHINE));

        return certificates;
    }

    private static List<X509Certificate> readStore(int location)
            throws Exception {

        List<X509Certificate> certificates = new ArrayList<>();

        WinCrypt.HCERTSTORE store = Crypt32.INSTANCE.CertOpenStore(
                new WinCrypt.CertStoreProviderName(
                        WinCrypt.CERT_STORE_PROV_SYSTEM_W),
                0,
                null,
                location
                    | WinCrypt.CERT_STORE_READONLY_FLAG
                    | WinCrypt.CERT_STORE_OPEN_EXISTING_FLAG,
                new WTypes.LPWSTR("CA")
        );

        if (store == null) {
            throw new IllegalStateException(
                    "Impossible d'ouvrir Windows CA : "
                    + Native.getLastError());
        }

        CertificateFactory factory =
                CertificateFactory.getInstance("X.509");

        try {
            WinCrypt.CERT_CONTEXT.ByReference context = null;

            while (true) {

                context = Crypt32.INSTANCE.CertEnumCertificatesInStore(
                        store,
                        context == null ? null : context.getPointer());

                if (context == null) {
                    break;
                }

                byte[] encoded =
                        context.pbCertEncoded.getByteArray(
                                0, context.cbCertEncoded);

                X509Certificate certificate =
                        (X509Certificate) factory.generateCertificate(
                                new ByteArrayInputStream(encoded));

                certificates.add(certificate);
            }

        } finally {
            Crypt32.INSTANCE.CertCloseStore(store, 0);
        }

        return certificates;
    }
}

