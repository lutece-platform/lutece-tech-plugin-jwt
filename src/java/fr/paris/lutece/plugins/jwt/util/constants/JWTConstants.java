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
package fr.paris.lutece.plugins.jwt.util.constants;

public class JWTConstants {
	
	/**
	 * token key
	 */
	public static final String JWT_KEY							= "token";
	
	/**
	 * token secret key
	 */
	public static final String SECRET_KEY 						= "secret_key";
	
	public static final String PAYLOAD_ROLE						= "role";
	/**
	 * The authorisation header
	 */
	public static final String AUTHORISATION_HEADER 			= "Authorization";
	
	/**
	 * The url login to obtain a JWT Token
	 */
	public static final String URL_LOGIN						= "/rest/jwt/login";
	
	/**
	 * The error message when user does not have JWT Token
	 */
	public static final String NO_JWT_TOKEN_MESSAGE				= "You do not have JWT access token";
	
	/**
	 * The error message when jwt's user token is expired
	 */
	public static final String EXPIRED_TOKEN_MESSAGE			= "The JWT access token have expired";
	
	/**
	 * The error message when the signature of request is incorrect
	 */
	public static final String WRONG_SIGNATURE					= "Wrong signature";
	
	/**
	 * 200 OK Message
	 */
	public static final String ACCESS_GRANTED					= "ACCES GRANTED";
	
	/**
	 * The error message when user does not have the role(s) to access to the webservice
	 */
	public static final String NO_ACCESS						= "You don't have access to webservices";
	
	/**
	 * The error message when user login/pwd is wrong
	 */
	public static final String LOGIN_ERROR						= "You are not authorized to signin";
	
	/**
	 * Name of webservice access role
	 */
	public static final String WS_ROLE							= "WS_ACCESS";
	
	
}
