package com.example.oauth2WithJwt.config.oauth2.service;

import com.example.oauth2WithJwt.config.auth.PrincipalDetails;
import com.example.oauth2WithJwt.config.oauth2.provider.FaceBookUserInfo;
import com.example.oauth2WithJwt.config.oauth2.provider.GoogleUserInfo;
import com.example.oauth2WithJwt.config.oauth2.provider.NaverUserInfo;
import com.example.oauth2WithJwt.config.oauth2.provider.OAUth2UserInfo;
import com.example.oauth2WithJwt.domain.User;
import com.example.oauth2WithJwt.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserService userService;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("PrincipalOauth2UserService() 실행 - Oauth 로그인 요청 진입");
        log.info("registartionId, OAuth2 = {}", userRequest.getClientRegistration());
        //어떤 registrationId를 통한 로그인인가

        log.info("TokenValue = {}", userRequest.getAccessToken());
        // 구글 로그인 버튼 클릭시 -> 구글 로그인 창 -> 로그인 완료 -> code 반환 (OAuth-Client 라이브러리) -> AccessToken 요청
        // : userRequest 정보를 얻음
        // userRequest 정보 -> 회원 프로필 받아야함 (loadUser함수) -> 회원 프로필 받음

        OAuth2User oAuth2User = super.loadUser(userRequest);
        log.info("getAttribue = {}", oAuth2User.getAttributes());
        // getAttribute에서 정보를 얻을 수 있음 -> 이를 통해서 자동 회원가입 등등의 과정을 가져갈 수 있다
        // oAuth2User 는 OAuth 서비스에서 가져온 유저의 정보를 담고 있다.

        OAUth2UserInfo oaUth2UserInfo = null;
        oaUth2UserInfo = getOauth2UserInfo(userRequest, oAuth2User, oaUth2UserInfo);

        PrincipalDetails principalDetails = getPrincipalDetails(oAuth2User, oaUth2UserInfo);
        log.info("principalDetails = {}", principalDetails.getAttributes());
        return principalDetails;
    }

    private OAUth2UserInfo getOauth2UserInfo(OAuth2UserRequest userRequest, OAuth2User oAuth2User, OAUth2UserInfo oaUth2UserInfo) {
        if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            log.info("google 요청");
            oaUth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        }

        if (userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
            log.info("facebook 요청");
            oaUth2UserInfo = new FaceBookUserInfo(oAuth2User.getAttributes());
        }

        if (userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
            log.info("naver 요청");
            oaUth2UserInfo = new NaverUserInfo((Map<String, Object>) oAuth2User.getAttributes().get("response"));
        }

        return oaUth2UserInfo;
    }
    private PrincipalDetails getPrincipalDetails(OAuth2User oAuth2User, OAUth2UserInfo oaUth2UserInfo) {
        String provider = oaUth2UserInfo.getProvider();
        // google of facebook
        String providerId = oaUth2UserInfo.getProviderId();
        // 넘어오는 ProviderId
        String email = oaUth2UserInfo.getEmail();
        // email값
        String username = provider + "_" + providerId;
        // google_1032140005 이런식으로 생성됨
        String password = bCryptPasswordEncoder.encode("getInThere");
        // 아무 값이 넣어줌(필요없어서)

        User user = userService.findByUsername(username);

        if (user == null) {
            log.info("회원가입 처리");
            user = User.builder()
                    .username(username)
                    .password(password)
                    .provider(provider)
                    .providerId(providerId)
                    .email(email)
                    .build();

            userService.save(user);
            return new PrincipalDetails(user, oAuth2User.getAttributes());
        }

        log.info("이미 존재하는 OAuth 아이디");
        return new PrincipalDetails(user, oAuth2User.getAttributes());
    }
}
