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
package fr.paris.lutece.plugins.jwt.service;

import java.security.Key;
import java.sql.Timestamp;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import fr.paris.lutece.plugins.jwt.util.constants.JWTConstants;

import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.lang.time.DateUtils;

import fr.paris.lutece.portal.business.rbac.AdminRole;
import fr.paris.lutece.portal.business.user.AdminUser;
import fr.paris.lutece.portal.service.util.AppPathService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JWTTokenProvider {
	
	/**
	 * Create the JWT Token 
	 * 
	 * @param request
	 * 			the HTTPSerletRequest
	 * @param subject
	 * 			subjet param of the payload
	 * @param tokenValidityMin
	 * 			Minutes before the jwt token expired
	 * @param roles
	 * 				user's roles
	 * @param user
	 * 			AdminUser object
	 * @return
	 */
	public String createJWT( HttpServletRequest request, int intTokenValidityMin, Map<String, AdminRole> mapRoles, AdminUser user) {
		  
	    Map<String, Object> header = new HashMap<String, Object>( );
	    header.put("alg", "HS256");
	    header.put( Header.TYPE, Header.JWT_TYPE );
	    Date date = new Date();
	    	
	    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
	    
	    byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary( JWTConstants.SECRET_KEY );
	    Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());
	    
	    JwtBuilder builder = Jwts.builder( )
	            .setHeader( header )
	            .setIssuer( AppPathService.getWebAppPath( ) )
	            .setIssuedAt( new Timestamp( date.getTime() ) )
	            .setAudience( AppPathService.getBaseUrl( request ) )
	            .setSubject( String.valueOf( user.getUserId( ) ) )
	            .claim( JWTConstants.PAYLOAD_ROLE, mapRoles ) 	
	            .signWith( signatureAlgorithm, signingKey );
	  
	    if (intTokenValidityMin > 0) {
	        date = DateUtils.addMinutes(date, intTokenValidityMin);
	        builder.setExpiration(date);
	    }  
	  
	    return builder.compact();
	}
	
	/**
	 * Decode and return the params of the jwt token payload
	 * 
	 * @param jwt
	 * @return
	 */
	public static Claims decodeJWT(String jwt) {
	    return  Jwts.parser()
	            .setSigningKey(DatatypeConverter.parseBase64Binary( JWTConstants.SECRET_KEY ))
	            .parseClaimsJws(jwt).getBody();
	}

}
