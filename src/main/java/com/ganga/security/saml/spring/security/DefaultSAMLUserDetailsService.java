package com.ganga.security.saml.spring.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

@Service
public class DefaultSAMLUserDetailsService implements SAMLUserDetailsService {

		private static final Logger LOG = LoggerFactory.getLogger(DefaultSAMLUserDetailsService.class);

		public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
			LOG.info("Login received for user {}", credential.getNameID().getValue());
			return new SAMLUserDetails(credential);
		}

}
