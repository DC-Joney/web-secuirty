package com.security.starter.support.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;

class JWKSelectorFactory {
    private final JWKSelectorFactory.DelegateSelectorFactory delegate;

    JWKSelectorFactory(JWSAlgorithm expectedJWSAlgorithm) {
        this.delegate = new JWKSelectorFactory.DelegateSelectorFactory(expectedJWSAlgorithm);
    }

    JWKSelector createSelector(JWSHeader jwsHeader) {
        return new JWKSelector(this.delegate.createJWKMatcher(jwsHeader));
    }

    /**
     * Used to expose the protected {@link #createJWKMatcher(JWSHeader)} method.
     */
    private static class DelegateSelectorFactory extends JWSVerificationKeySelector {
        /**
         * Creates a new JWS verification key selector.
         *
         * @param jwsAlg    The expected JWS algorithm for the objects to be
         *                  verified. Must not be {@code null}.
         */
        public DelegateSelectorFactory(JWSAlgorithm jwsAlg) {
            super(jwsAlg, (jwkSelector, context) -> {
                throw new KeySourceException("JWKSelectorFactory is only intended for creating a selector");
            });
        }

        @Override
        public JWKMatcher createJWKMatcher(JWSHeader jwsHeader) {
            return super.createJWKMatcher(jwsHeader);
        }
    }
}
