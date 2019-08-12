/*
 * Copyright (c) 2002-2019, Mairie de Paris
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice
 *     and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice
 *     and the following disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *
 *  3. Neither the name of 'Mairie de Paris' nor 'Lutece' nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * License 1.0
 */
package fr.paris.lutece.plugins.jwt.web.rs;

import java.util.Map;
import javax.inject.Inject;
import javax.inject.Named;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import org.json.JSONException;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import fr.paris.lutece.plugins.jwt.service.JWTTokenProvider;
import fr.paris.lutece.plugins.jwt.util.constants.JWTConstants;
import fr.paris.lutece.plugins.rest.service.RestConstants;
import fr.paris.lutece.portal.business.rbac.AdminRole;
import fr.paris.lutece.portal.business.user.AdminUser;
import fr.paris.lutece.portal.business.user.AdminUserHome;
import fr.paris.lutece.portal.business.user.authentication.LuteceDefaultAdminAuthentication;
import fr.paris.lutece.portal.business.user.authentication.LuteceDefaultAdminUserDAO;
import fr.paris.lutece.portal.service.admin.AdminAuthenticationService;
import fr.paris.lutece.portal.service.spring.SpringContextService;
import fr.paris.lutece.portal.service.util.AppLogService;
import fr.paris.lutece.portal.service.util.AppPropertiesService;
import net.sf.json.JSONObject;

@Path( RestConstants.BASE_PATH+"jwt" )
public class JWTResource  {

	private static final String TOKEN_VALIDITY           		 			 = "jwt.token.validity";

	private static final String USERNAME_PARAM								 = "username";

	private static final String PASSWORD_PARAM								 = "password";

	@Inject
	private JWTTokenProvider _jwtTokenProvider;

	@Inject
	@Named("admin.authService")
	private AdminAuthenticationService _adminAuth;

	/**
	 * Signin method to obtain a JWT Token for the webservices
	 * @param request
	 * 			The HttpServletRequest
	 * @param strJsonData
	 * 			params of the request
	 * @return
	 * 			the jwt token
	 */
	@POST
	@Path( "/login" )
	@Consumes( MediaType.APPLICATION_JSON )
	@Produces( MediaType.APPLICATION_JSON ) 
	public String signin( @Context HttpServletRequest request, String strJsonData )
	{
		org.json.JSONObject jsonRequest = new org.json.JSONObject(strJsonData);
		LuteceDefaultAdminUserDAO dao = new LuteceDefaultAdminUserDAO( );

		try {
			LuteceDefaultAdminAuthentication adminAuth = getLuteceDefaultAdminAuthentication();
			AdminUser user = adminAuth.login(jsonRequest.get( USERNAME_PARAM ).toString( ), jsonRequest.get( PASSWORD_PARAM ).toString( ), request );
			Map<String, AdminRole> mapUserRoles = AdminUserHome.getRolesListForUser( user.getUserId() );
			String jwt = _jwtTokenProvider.createJWT( request, AppPropertiesService.getPropertyInt( TOKEN_VALIDITY, 0 ), mapUserRoles, user );
			JSONObject jwtToken = new JSONObject();
			jwtToken.accumulate( JWTConstants.JWT_KEY, jwt );
			return jwtToken.toString();				
		} catch (LoginException | JSONException e) {
			AppLogService.error( JWTConstants.LOGIN_ERROR );
			return null;
		}
	}

	/**
	 * Get the bean of LuteceDefaultAdminAuthentication
	 * @return
	 */
	private LuteceDefaultAdminAuthentication getLuteceDefaultAdminAuthentication( )
	{
		LuteceDefaultAdminAuthentication adminAuth = new LuteceDefaultAdminAuthentication( );
		LuteceDefaultAdminUserDAO dao = new LuteceDefaultAdminUserDAO( );
		AutowireCapableBeanFactory beanFactory = SpringContextService.getContext( ).getAutowireCapableBeanFactory( );
		beanFactory.autowireBean( dao );
		adminAuth.setDao( dao );
		beanFactory.autowireBean( adminAuth );
		return adminAuth;
	}

}
