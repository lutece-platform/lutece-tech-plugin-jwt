package fr.paris.lutece.plugins.jwt.business.dao.impl;

public interface IJWTUserDAO {

	boolean checkAuthentication( String username, String password );
}
	