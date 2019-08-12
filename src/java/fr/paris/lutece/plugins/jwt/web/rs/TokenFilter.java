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

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.ConfigurableApplicationContext;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.jersey.api.core.DefaultResourceConfig;
import com.sun.jersey.api.core.ResourceConfig;
import com.sun.jersey.spi.container.WebApplication;
import com.sun.jersey.spi.container.servlet.ServletContainer;
import com.sun.jersey.spi.container.servlet.WebConfig;
import com.sun.jersey.spi.spring.container.SpringComponentProviderFactory;

import fr.paris.lutece.plugins.jwt.service.JWTTokenProvider;
import fr.paris.lutece.plugins.jwt.util.annotation.RequiresPermissions;
import fr.paris.lutece.plugins.jwt.util.constants.JWTConstants;
import fr.paris.lutece.portal.business.rbac.AdminRole;
import fr.paris.lutece.portal.business.rbac.RBAC;
import fr.paris.lutece.portal.business.user.AdminUser;
import fr.paris.lutece.portal.service.admin.AdminAuthenticationService;
import fr.paris.lutece.portal.service.rbac.RBACResource;
import fr.paris.lutece.portal.service.rbac.RBACService;
import fr.paris.lutece.portal.service.spring.SpringContextService;
import fr.paris.lutece.portal.service.util.AppLogService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.SignatureException;

public class TokenFilter extends ServletContainer  {

	private JWTTokenProvider _jwtTokenProvider;

	@Inject
	@Named("admin.authService")
	private AdminAuthenticationService _adminAuth;
	
	private Map<String, Map<String,String> > _mapWSRoles;


	/**
	 *
	 * {@inheritDoc}
	 */
	@Override
	protected ResourceConfig getDefaultResourceConfig( Map<String, Object> props, WebConfig webConfig )
			throws ServletException
	{
		return new DefaultResourceConfig(  );
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void initiate( ResourceConfig rc, WebApplication wa )
	{
		_mapWSRoles = new HashMap<String, Map<String,String> >( );
		wa.initiate( rc, new SpringComponentProviderFactory( rc, ( ConfigurableApplicationContext ) SpringContextService.getContext( ) ) );
		for ( Class<?> clazz :rc.getClasses( ))  {
			if (clazz.isAnnotationPresent( javax.ws.rs.Path.class ) ) {
				for (int i =0; i< clazz.getDeclaredMethods( ).length; i++) {
					if(clazz.getDeclaredMethods( )[i].isAnnotationPresent(  javax.ws.rs.Path.class ) && clazz.getDeclaredMethods( )[i].isAnnotationPresent( fr.paris.lutece.plugins.jwt.util.annotation.RequiresPermissions.class ) )
					{
						Map<String, String> newMapPermission = new HashMap<>();
						newMapPermission.put(clazz.getDeclaredMethods( )[i].getDeclaredAnnotation( fr.paris.lutece.plugins.jwt.util.annotation.RequiresPermissions.class ).resource(), 
											clazz.getDeclaredMethods( )[i].getDeclaredAnnotation( fr.paris.lutece.plugins.jwt.util.annotation.RequiresPermissions.class ).permission());
						_mapWSRoles.
							put(clazz.getDeclaredAnnotation(javax.ws.rs.Path.class ).value() + "/" + clazz.getDeclaredMethods( )[i].getDeclaredAnnotation( javax.ws.rs.Path.class ).value( ), newMapPermission);
					}
				}			
			}
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException,
	ServletException {

		HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;
		HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        ObjectMapper oMapper = new ObjectMapper();
        AdminUser user = new AdminUser();

		try {
			
			if( !httpServletRequest.getRequestURI().substring(httpServletRequest.getContextPath().length()).equals( JWTConstants.URL_LOGIN ) )
			{
				String jwt = resolveToken(httpServletRequest);
				if( jwt != null )
				{ 
					Claims claims = _jwtTokenProvider.decodeJWT(jwt);
					Map<String, String > mapRequiredRole = _mapWSRoles.get( httpServletRequest.getServletPath( ) );
					 Map.Entry<String,String> entry = mapRequiredRole.entrySet().iterator().next();

			        Map<String, AdminRole> mapRolesPayload = oMapper.convertValue(claims.get(JWTConstants.PAYLOAD_ROLE), Map.class);
					user.setRoles(mapRolesPayload);

					if ( RBACService.isAuthorized(entry.getKey(), RBAC.WILDCARD_RESOURCES_ID, entry.getValue(), user) )
					{ 
						filterChain.doFilter( servletRequest, servletResponse );
					} else {
						AppLogService.debug( JWTConstants.NO_ACCESS);
						servletResponse.getWriter().println(JWTConstants.NO_ACCESS);
						httpServletResponse.sendError(HttpServletResponse.SC_FORBIDDEN );
					}
				} else 
				{            
					AppLogService.debug( JWTConstants.NO_JWT_TOKEN_MESSAGE);
					servletResponse.getWriter().println(JWTConstants.NO_JWT_TOKEN_MESSAGE);
					httpServletResponse.sendError(HttpServletResponse.SC_FORBIDDEN );
				}            	
			} else {
				filterChain.doFilter(servletRequest, servletResponse);
			}

		} catch (ExpiredJwtException eje) {
			AppLogService.error("Security exception for user {} - {}" + eje.getClaims().getSubject() + eje.getMessage());
			((HttpServletResponse) servletResponse).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			AppLogService.debug("Exception " + eje.getMessage(), eje);
			servletResponse.getWriter().println(JWTConstants.EXPIRED_TOKEN_MESSAGE);
			httpServletResponse.sendError(HttpServletResponse.SC_FORBIDDEN );
		} catch (SignatureException e)
		{
			AppLogService.error("Security exception for user {} - {}" + e.getMessage());
			((HttpServletResponse) servletResponse).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			AppLogService.debug("Exception " + e.getMessage(), e);
			servletResponse.getWriter().println(JWTConstants.WRONG_SIGNATURE);
			httpServletResponse.sendError(HttpServletResponse.SC_FORBIDDEN );
		}
	}

	/**
	 * Return the bearer token contains in the request
	 * 
	 * @param request
	 * 			the HTTPServletRequest
	 * @return
	 * 			The token if presents
	 */
	public String resolveToken(HttpServletRequest request) 
	{
		String bearerToken = request.getHeader(JWTConstants.AUTHORISATION_HEADER);
		if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
			String jwt = bearerToken.substring(7, bearerToken.length());
			return jwt;
		}
		return null;
	}

}	