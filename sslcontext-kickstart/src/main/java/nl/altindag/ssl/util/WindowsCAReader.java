/*
 * Copyright 2026 Goldex60.
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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public final class WindowsCAReader {

    private static final int CRYPT_E_NOT_FOUND = 0x80092004;
    private static final int ERROR_NO_MORE_FILES = 18;

    private WindowsCAReader() {
    }

    public static List<X509Certificate> loadCertificates()
            throws Exception {

        Set<X509Certificate> certificates = new LinkedHashSet<>();

        certificates.addAll(readStore(
                WinCrypt.CERT_SYSTEM_STORE_CURRENT_USER,
                "CURRENT_USER"));

        certificates.addAll(readStore(
                WinCrypt.CERT_SYSTEM_STORE_LOCAL_MACHINE,
                "LOCAL_MACHINE"));

        return new ArrayList<>(certificates);
    }

    private static List<X509Certificate> readStore(
            int location, String locationName) throws Exception {

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
            throw nativeError("CertOpenStore", locationName,
                    Native.getLastError());
        }

        List<X509Certificate> certificates = new ArrayList<>();
        WinCrypt.CERT_CONTEXT.ByReference context = null;
        Throwable failure = null;

        try {
            CertificateFactory factory =
                    CertificateFactory.getInstance("X.509");

            while (true) {
                com.sun.jna.Pointer previous =
                        context == null ? null : context.getPointer();

                context = null;

                WinCrypt.CERT_CONTEXT.ByReference next =
                        Crypt32.INSTANCE.CertEnumCertificatesInStore(
                                store, previous);

                int error = next == null ? Native.getLastError() : 0;

                if (next == null) {
                    if (error == CRYPT_E_NOT_FOUND
                            || error == ERROR_NO_MORE_FILES) {
                        break;
                    }
                    throw nativeError(
                            "CertEnumCertificatesInStore",
                            locationName, error);
                }

                context = next;

                byte[] encoded = context.pbCertEncoded.getByteArray(
                        0, context.cbCertEncoded);

                X509Certificate certificate =
                        (X509Certificate) factory.generateCertificate(
                                new ByteArrayInputStream(encoded));

                certificates.add(certificate);
            }

            return certificates;

        } catch (Exception | Error e) {
            failure = e;
            throw e;

        } finally {

            if (context != null) {
                Crypt32.INSTANCE.CertFreeCertificateContext(context);
            }

            boolean closed = Crypt32.INSTANCE.CertCloseStore(store, 0);

            if (!closed) {
                IllegalStateException closeError = nativeError(
                        "CertCloseStore",
                        locationName,
                        Native.getLastError());

                if (failure != null) {
                    failure.addSuppressed(closeError);
                } else {
                    throw closeError;
                }
            }
        }
    }

    private static IllegalStateException nativeError(
            String operation, String location, int error) {

        return new IllegalStateException(
                operation + " failed for Windows CA/"
                        + location + " (Win32 error: 0x"
                        + String.format("%08X", error) + ")");
    }
}

