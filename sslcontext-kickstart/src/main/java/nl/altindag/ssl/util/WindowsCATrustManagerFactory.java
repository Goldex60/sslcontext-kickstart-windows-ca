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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.X509ExtendedTrustManager;

import java.security.KeyStore;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

final class WindowsCATrustManagerFactory {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(
                    WindowsCATrustManagerFactory.class);

    private WindowsCATrustManagerFactory() {
    }

    /**
     * Creates a PKIX TrustManager using:
     *
     * - Windows ROOT stores as trust anchor sources
     * - Windows CA stores as intermediate certificate sources
     *
     * Intermediate certificates are used for certificate path
     * building and are not treated as trust anchors.
     */
    static X509ExtendedTrustManager create() throws Exception {

        if (OperatingSystem.get() != OperatingSystem.WINDOWS) {
            throw new UnsupportedOperationException(
                    "Windows CA is only available on Windows");
        }

        LOGGER.info("Initializing Windows CA TrustManager");

        // 1. Load trusted root certificates from Windows stores
        Set<TrustAnchor> trustAnchors =
                loadWindowsTrustAnchors();

        if (trustAnchors.isEmpty()) {
            throw new IllegalStateException(
                    "No trusted root certificates found");
        }

        LOGGER.info(
                "Loaded {} Windows trust anchors",
                trustAnchors.size());

        // 2. Load intermediate certificates from Windows CA stores
        List<X509Certificate> intermediates =
                WindowsCAReader.loadCertificates();

        LOGGER.info(
                "Loaded {} Windows CA certificates",
                intermediates.size());

        // 3. Configure PKIX parameters
        PKIXBuilderParameters parameters =
                new PKIXBuilderParameters(
                        trustAnchors,
                        new X509CertSelector());

        // 4. Add intermediate certificates for path building without treating them as trust anchors.
        CertStore intermediateStore =
                CertStore.getInstance(
                        "Collection",
                        new CollectionCertStoreParameters(
                                intermediates));

        parameters.addCertStore(intermediateStore);

        // 5. Create the PKIX TrustManager
        CertPathTrustManagerParameters managerParameters =
                new CertPathTrustManagerParameters(
                        parameters);

        X509ExtendedTrustManager trustManager =
                TrustManagerUtils.createTrustManager(
                        managerParameters,
                        "PKIX");

        LOGGER.info(
                "Windows CA PKIX TrustManager initialized");

        return trustManager;
    }

    /**
     * Loads trusted certificates from Windows ROOT stores
     * and converts them into PKIX trust anchors.
     */
    private static Set<TrustAnchor> loadWindowsTrustAnchors()
            throws Exception {

        Set<TrustAnchor> trustAnchors =
                new HashSet<>();

        List<String> storeTypes = new ArrayList<>();

        storeTypes.add("Windows-ROOT");
        storeTypes.add("Windows-ROOT-LOCALMACHINE");
        storeTypes.add("Windows-ROOT-CURRENTUSER");

        for (String storeType : storeTypes) {

            LOGGER.debug(
                    "Loading Windows root store: {}",
                    storeType);

            Optional<KeyStore> optionalStore =
                    KeyStoreUtils.createKeyStoreIfAvailable(
                            storeType,
                            null);

            if (!optionalStore.isPresent()) {
                LOGGER.debug(
                        "Windows store not available: {}",
                        storeType);
                continue;
            }

            KeyStore store = optionalStore.get();

            Enumeration<String> aliases =
                    store.aliases();

            int count = 0;

            while (aliases.hasMoreElements()) {

                String alias = aliases.nextElement();

                // Include only trusted certificate entries.
                if (!store.isCertificateEntry(alias)) {
                    continue;
                }

                java.security.cert.Certificate certificate =
                        store.getCertificate(alias);

                if (!(certificate instanceof X509Certificate)) {
                    continue;
                }

                X509Certificate x509 =
                        (X509Certificate) certificate;

                TrustAnchor anchor =
                        new TrustAnchor(x509, null);

                trustAnchors.add(anchor);
                count++;
            }

            LOGGER.info(
                    "Loaded {} certificates from {}",
                    count,
                    storeType);
        }

        return trustAnchors;
    }
}

