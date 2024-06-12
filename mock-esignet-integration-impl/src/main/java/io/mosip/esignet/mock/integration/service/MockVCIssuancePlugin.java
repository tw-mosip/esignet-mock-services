package io.mosip.esignet.mock.integration.service;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.crypto.Cipher;

import io.mosip.esignet.api.exception.VCIExchangeException;
import io.mosip.esignet.api.util.ErrorConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import foundation.identity.jsonld.ConfigurableDocumentLoader;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import io.mosip.esignet.api.dto.VCRequestDto;
import io.mosip.esignet.api.dto.MdocRequestDto;
import io.mosip.esignet.api.dto.VCResult;
import io.mosip.esignet.api.spi.VCIssuancePlugin;
import io.mosip.esignet.core.dto.OIDCTransaction;
import io.mosip.esignet.core.dto.vci.ParsedAccessToken;
import io.mosip.esignet.core.exception.EsignetException;
import io.mosip.esignet.core.util.IdentityProviderUtil;
import io.mosip.kernel.core.keymanager.spi.KeyStore;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerConstant;
import io.mosip.kernel.keymanagerservice.entity.KeyAlias;
import io.mosip.kernel.keymanagerservice.helper.KeymanagerDBHelper;
import io.mosip.kernel.signature.dto.JWTSignatureRequestDto;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.service.SignatureService;
import lombok.extern.slf4j.Slf4j;

@ConditionalOnProperty(value = "mosip.esignet.integration.vci-plugin", havingValue = "MockVCIssuancePlugin")
@Component
@Slf4j
public class MockVCIssuancePlugin implements VCIssuancePlugin {
	@Autowired
	private SignatureService signatureService;

	@Autowired
	private ParsedAccessToken parsedAccessToken;

	@Autowired
	private CacheManager cacheManager;

	@Autowired
	private KeyStore keyStore;

	@Autowired
	private KeymanagerDBHelper dbHelper;

	private ConfigurableDocumentLoader confDocumentLoader = null;

	@Value("${mosip.esignet.mock.vciplugin.verification-method}")
	private String verificationMethod;

	@Value("${mosip.esignet.mock.authenticator.get-identity-url}")
	private String getIdentityUrl;

	@Value("${mosip.esignet.cache.security.secretkey.reference-id}")
	private String cacheSecretKeyRefId;

	@Value("${mosip.esignet.cache.security.algorithm-name}")
	private String aesECBTransformation;

	@Value("${mosip.esignet.cache.secure.individual-id}")
	private boolean secureIndividualId;

	@Value("${mosip.esignet.cache.store.individual-id}")
	private boolean storeIndividualId;

	@Value("#{${mosip.esignet.mock.vciplugin.vc-credential-contexts:{'https://www.w3.org/2018/credentials/v1','https://schema.org/'}}}")
	private List<String> vcCredentialContexts;

	public static final String UTC_DATETIME_PATTERN = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";

	public static final String OIDC_SERVICE_APP_ID = "OIDC_SERVICE";

	@Override
	public VCResult<JsonLDObject> getVerifiableCredentialWithLinkedDataProof(VCRequestDto vcRequestDto, String holderId,
			Map<String, Object> identityDetails) throws VCIExchangeException {
		JsonLDObject vcJsonLdObject = null;
		try {
			VCResult<JsonLDObject> vcResult = new VCResult<>();
			vcJsonLdObject = buildDummyJsonLDWithLDProof(holderId);
			vcResult.setCredential(vcJsonLdObject);
			vcResult.setFormat("ldp_vc");
			return vcResult;
		} catch (Exception e) {
			log.error("Failed to build mock VC", e);
		}
		throw new VCIExchangeException();
	}

	private JsonLDObject buildDummyJsonLDWithLDProof(String holderId)
			throws IOException, GeneralSecurityException, JsonLDException, URISyntaxException {
		OIDCTransaction transaction = getUserInfoTransaction(parsedAccessToken.getAccessTokenHash());
		Map<String, Object> formattedMap = null;
		try{
			formattedMap = getIndividualData(transaction);
		} catch(Exception e) {
			log.error("Unable to get KYC exchange data from MOCK", e);
		}

		Map<String, Object> verCredJsonObject = new HashMap<>();
		verCredJsonObject.put("@context", vcCredentialContexts);
		verCredJsonObject.put("type", Arrays.asList("VerifiableCredential", "MOSIPVerifiableCredential"));
		verCredJsonObject.put("id", "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5");
		verCredJsonObject.put("issuer", "did:example:123456789");
		verCredJsonObject.put("issuanceDate", getUTCDateTime());
		verCredJsonObject.put("credentialSubject", formattedMap);

		JsonLDObject vcJsonLdObject = JsonLDObject.fromJsonObject(verCredJsonObject);
		vcJsonLdObject.setDocumentLoader(confDocumentLoader);
		// vc proof
		Date created = Date
				.from(LocalDateTime
						.parse((String) verCredJsonObject.get("issuanceDate"),
								DateTimeFormatter.ofPattern(UTC_DATETIME_PATTERN))
						.atZone(ZoneId.systemDefault()).toInstant());
		LdProof vcLdProof = LdProof.builder().defaultContexts(false).defaultTypes(false).type("RsaSignature2018")
				.created(created).proofPurpose("assertionMethod")
				.verificationMethod(URI.create(verificationMethod))
				.build();

		URDNA2015Canonicalizer canonicalizer = new URDNA2015Canonicalizer();
		byte[] vcSignBytes = canonicalizer.canonicalize(vcLdProof, vcJsonLdObject);
		String vcEncodedData = CryptoUtil.encodeToURLSafeBase64(vcSignBytes);

		JWTSignatureRequestDto jwtSignatureRequestDto = new JWTSignatureRequestDto();
		jwtSignatureRequestDto.setApplicationId(OIDC_SERVICE_APP_ID);
		jwtSignatureRequestDto.setReferenceId("");
		jwtSignatureRequestDto.setIncludePayload(false);
		jwtSignatureRequestDto.setIncludeCertificate(true);
		jwtSignatureRequestDto.setIncludeCertHash(true);
		jwtSignatureRequestDto.setDataToSign(vcEncodedData);
		JWTSignatureResponseDto responseDto = signatureService.jwtSign(jwtSignatureRequestDto);
		LdProof ldProofWithJWS = LdProof.builder().base(vcLdProof).defaultContexts(false)
				.jws(responseDto.getJwtSignedData()).build();
		ldProofWithJWS.addToJsonLDObject(vcJsonLdObject);
		return vcJsonLdObject;
	}

	private Map<String, Object> getIndividualData(OIDCTransaction transaction){
		String individualId = getIndividualId(transaction);
		if (individualId!=null){
			Map<String, Object> res = new RestTemplate().getForObject(
				getIdentityUrl+"/"+individualId,
				HashMap.class);
			res = (Map<String, Object>)res.get("response");
			Map<String, Object> ret = new HashMap<>();
			ret.put("vcVer", "VC-V1");
			ret.put("id", getIdentityUrl+"/"+individualId);
			ret.put("UIN", individualId);
			ret.put("name", res.get("name"));
			ret.put("fullName", res.get("fullName"));
			ret.put("gender", res.get("gender"));
			ret.put("dateOfBirth", res.get("dateOfBirth"));
			ret.put("email", res.get("email"));
			ret.put("phone", res.get("phone"));
			ret.put("addressLine1", res.get("streetAddress"));
			ret.put("province", res.get("locality"));
			ret.put("region", res.get("region"));
			ret.put("postalCode", res.get("postalCode"));
			ret.put("face", res.get("encodedPhoto"));
			return ret;
		} else {
			return new HashMap<>();
		}
	}

	protected String getIndividualId(OIDCTransaction transaction) {
		if(!storeIndividualId)
			return null;
		return secureIndividualId ? decryptIndividualId(transaction.getIndividualId()) : transaction.getIndividualId();
	}

	private String decryptIndividualId(String encryptedIndividualId) {
		try {
			Cipher cipher = Cipher.getInstance(aesECBTransformation);
			byte[] decodedBytes = IdentityProviderUtil.b64Decode(encryptedIndividualId);
			cipher.init(Cipher.DECRYPT_MODE, getSecretKeyFromHSM());
			return new String(cipher.doFinal(decodedBytes, 0, decodedBytes.length));
		} catch(Exception e) {
			log.error("Error Cipher Operations of provided secret data.", e);
			throw new EsignetException(io.mosip.esignet.core.constants.ErrorConstants.AES_CIPHER_FAILED);
		}
	}

	private Key getSecretKeyFromHSM() {
		String keyAlias = getKeyAlias(OIDC_SERVICE_APP_ID, cacheSecretKeyRefId);
		if (Objects.nonNull(keyAlias)) {
			return keyStore.getSymmetricKey(keyAlias);
		}
		throw new EsignetException(io.mosip.esignet.core.constants.ErrorConstants.NO_UNIQUE_ALIAS);
	}

	private String getKeyAlias(String keyAppId, String keyRefId) {
		Map<String, List<KeyAlias>> keyAliasMap = dbHelper.getKeyAliases(keyAppId, keyRefId, LocalDateTime.now(ZoneOffset.UTC));
		List<KeyAlias> currentKeyAliases = keyAliasMap.get(KeymanagerConstant.CURRENTKEYALIAS);
		if (!currentKeyAliases.isEmpty() && currentKeyAliases.size() == 1) {
			return currentKeyAliases.get(0).getAlias();
		}
		log.error("CurrentKeyAlias is not unique. KeyAlias count: {}", currentKeyAliases.size());
		throw new EsignetException(io.mosip.esignet.core.constants.ErrorConstants.NO_UNIQUE_ALIAS);
	}

	private static String getUTCDateTime() {
		return ZonedDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ofPattern(UTC_DATETIME_PATTERN));
	}

	@Override
	public VCResult<String> getVerifiableCredential(VCRequestDto vcRequestDto, String holderId,
			Map<String, Object> identityDetails) throws VCIExchangeException {
		throw new VCIExchangeException(ErrorConstants.NOT_IMPLEMENTED);
	}

	@Override
	public VCResult<String> getMDocVerifiableCredential(MdocRequestDto mdocRequestDto, String holderId, Map<String, Object> identityDetails) throws VCIExchangeException {
		VCResult<String> vcResult = new VCResult<>();
			vcResult.setCredential("v2dkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETG1uYW1lU3BhY2VzTWFwv3FvcmcuaXNvLjE4MDEzLjUuMYi/aGRpZ2VzdElEv2V2YWx1ZQBpYXR0cmlidXRlv2R0eXBlZm51bWJlcv9kdHlwZWZudW1iZXL/ZnJhbmRvbb9ldmFsdWVQXoMQ67WOCmmfjJebeBo0MmlhdHRyaWJ1dGW/ZHR5cGVqYnl0ZVN0cmluZ/9kdHlwZWpieXRlU3RyaW5n/3FlbGVtZW50SWRlbnRpZmllcr9ldmFsdWVrZmFtaWx5X25hbWVpYXR0cmlidXRlv2R0eXBlanRleHRTdHJpbmf/ZHR5cGVqdGV4dFN0cmluZ/9sZWxlbWVudFZhbHVlv2V2YWx1ZWNEb2VpYXR0cmlidXRlv2R0eXBlanRleHRTdHJpbmf/ZHR5cGVqdGV4dFN0cmluZ///v2hkaWdlc3RJRL9ldmFsdWUBaWF0dHJpYnV0Zb9kdHlwZWZudW1iZXL/ZHR5cGVmbnVtYmVy/2ZyYW5kb22/ZXZhbHVlUA4rtAfk+fNFfFMrfhgr7lFpYXR0cmlidXRlv2R0eXBlamJ5dGVTdHJpbmf/ZHR5cGVqYnl0ZVN0cmluZ/9xZWxlbWVudElkZW50aWZpZXK/ZXZhbHVlamdpdmVuX25hbWVpYXR0cmlidXRlv2R0eXBlanRleHRTdHJpbmf/ZHR5cGVqdGV4dFN0cmluZ/9sZWxlbWVudFZhbHVlv2V2YWx1ZWRKb2huaWF0dHJpYnV0Zb9kdHlwZWp0ZXh0U3RyaW5n/2R0eXBlanRleHRTdHJpbmf//79oZGlnZXN0SUS/ZXZhbHVlAmlhdHRyaWJ1dGW/ZHR5cGVmbnVtYmVy/2R0eXBlZm51bWJlcv9mcmFuZG9tv2V2YWx1ZVDOIee9aGF8ZY+6qPr5mZkaaWF0dHJpYnV0Zb9kdHlwZWpieXRlU3RyaW5n/2R0eXBlamJ5dGVTdHJpbmf/cWVsZW1lbnRJZGVudGlmaWVyv2V2YWx1ZW9pc3N1aW5nX2NvdW50cnlpYXR0cmlidXRlv2R0eXBlanRleHRTdHJpbmf/ZHR5cGVqdGV4dFN0cmluZ/9sZWxlbWVudFZhbHVlv2V2YWx1ZWJVU2lhdHRyaWJ1dGW/ZHR5cGVqdGV4dFN0cmluZ/9kdHlwZWp0ZXh0U3RyaW5n//+/aGRpZ2VzdElEv2V2YWx1ZQNpYXR0cmlidXRlv2R0eXBlZm51bWJlcv9kdHlwZWZudW1iZXL/ZnJhbmRvbb9ldmFsdWVQwIX9KovjWk9qM63ECjVQKmlhdHRyaWJ1dGW/ZHR5cGVqYnl0ZVN0cmluZ/9kdHlwZWpieXRlU3RyaW5n/3FlbGVtZW50SWRlbnRpZmllcr9ldmFsdWVvZG9jdW1lbnRfbnVtYmVyaWF0dHJpYnV0Zb9kdHlwZWp0ZXh0U3RyaW5n/2R0eXBlanRleHRTdHJpbmf/bGVsZW1lbnRWYWx1Zb9ldmFsdWVoMTIzNDU2NzhpYXR0cmlidXRlv2R0eXBlanRleHRTdHJpbmf/ZHR5cGVqdGV4dFN0cmluZ///v2hkaWdlc3RJRL9ldmFsdWUEaWF0dHJpYnV0Zb9kdHlwZWZudW1iZXL/ZHR5cGVmbnVtYmVy/2ZyYW5kb22/ZXZhbHVlUL+K+ZBmkmazHAFXFBN4LAFpYXR0cmlidXRlv2R0eXBlamJ5dGVTdHJpbmf/ZHR5cGVqYnl0ZVN0cmluZ/9xZWxlbWVudElkZW50aWZpZXK/ZXZhbHVlamlzc3VlX2RhdGVpYXR0cmlidXRlv2R0eXBlanRleHRTdHJpbmf/ZHR5cGVqdGV4dFN0cmluZ/9sZWxlbWVudFZhbHVlv2V2YWx1ZWoyMDIzLTAxLTAxaWF0dHJpYnV0Zb9kdHlwZWp0ZXh0U3RyaW5n/2R0eXBlanRleHRTdHJpbmf//79oZGlnZXN0SUS/ZXZhbHVlBWlhdHRyaWJ1dGW/ZHR5cGVmbnVtYmVy/2R0eXBlZm51bWJlcv9mcmFuZG9tv2V2YWx1ZVBDnAAL+QsxQkFju6lTyC5FaWF0dHJpYnV0Zb9kdHlwZWpieXRlU3RyaW5n/2R0eXBlamJ5dGVTdHJpbmf/cWVsZW1lbnRJZGVudGlmaWVyv2V2YWx1ZWtleHBpcnlfZGF0ZWlhdHRyaWJ1dGW/ZHR5cGVqdGV4dFN0cmluZ/9kdHlwZWp0ZXh0U3RyaW5n/2xlbGVtZW50VmFsdWW/ZXZhbHVlajIwNDMtMDEtMDFpYXR0cmlidXRlv2R0eXBlanRleHRTdHJpbmf/ZHR5cGVqdGV4dFN0cmluZ///v2hkaWdlc3RJRL9ldmFsdWUGaWF0dHJpYnV0Zb9kdHlwZWZudW1iZXL/ZHR5cGVmbnVtYmVy/2ZyYW5kb22/ZXZhbHVlUHmXNP0IyDHvKhu4iktUERBpYXR0cmlidXRlv2R0eXBlamJ5dGVTdHJpbmf/ZHR5cGVqYnl0ZVN0cmluZ/9xZWxlbWVudElkZW50aWZpZXK/ZXZhbHVlamJpcnRoX2RhdGVpYXR0cmlidXRlv2R0eXBlanRleHRTdHJpbmf/ZHR5cGVqdGV4dFN0cmluZ/9sZWxlbWVudFZhbHVlv2V2YWx1ZWoyMDAzLTAxLTAxaWF0dHJpYnV0Zb9kdHlwZWp0ZXh0U3RyaW5n/2R0eXBlanRleHRTdHJpbmf//79oZGlnZXN0SUS/ZXZhbHVlB2lhdHRyaWJ1dGW/ZHR5cGVmbnVtYmVy/2R0eXBlZm51bWJlcv9mcmFuZG9tv2V2YWx1ZVAFCLYlz493l3uZ1hW/7r0AaWF0dHJpYnV0Zb9kdHlwZWpieXRlU3RyaW5n/2R0eXBlamJ5dGVTdHJpbmf/cWVsZW1lbnRJZGVudGlmaWVyv2V2YWx1ZXJkcml2aW5nX3ByaXZpbGVnZXNpYXR0cmlidXRlv2R0eXBlanRleHRTdHJpbmf/ZHR5cGVqdGV4dFN0cmluZ/9sZWxlbWVudFZhbHVlv2V2YWx1ZYG/ZXZhbHVlv3V2ZWhpY2xlX2NhdGVnb3J5X2NvZGW/ZXZhbHVlYUFpYXR0cmlidXRlv2R0eXBlanRleHRTdHJpbmf/ZHR5cGVqdGV4dFN0cmluZ/9qaXNzdWVfZGF0Zb9ldmFsdWVqMjAyMy0wMS0wMWlhdHRyaWJ1dGW/ZHR5cGVqdGV4dFN0cmluZ/9kdHlwZWp0ZXh0U3RyaW5n/2tleHBpcnlfZGF0Zb9ldmFsdWVqMjA0My0wMS0wMWlhdHRyaWJ1dGW/ZHR5cGVqdGV4dFN0cmluZ/9kdHlwZWp0ZXh0U3RyaW5n//9pYXR0cmlidXRlv2R0eXBlY21hcP9kdHlwZWNtYXD/aWF0dHJpYnV0Zb9kdHlwZWRsaXN0/2R0eXBlZGxpc3T/////");
			vcResult.setFormat("mso_mdoc");
			return vcResult;
	}

	public OIDCTransaction getUserInfoTransaction(String accessTokenHash) {
		return cacheManager.getCache(io.mosip.esignet.core.constants.Constants.USERINFO_CACHE).get(accessTokenHash, OIDCTransaction.class);
	}
}
