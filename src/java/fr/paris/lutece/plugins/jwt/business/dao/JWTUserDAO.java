package fr.paris.lutece.plugins.jwt.business.dao;

import fr.paris.lutece.plugins.jwt.business.dao.impl.IJWTUserDAO;
import fr.paris.lutece.plugins.jwt.business.entities.JWTUser;
import fr.paris.lutece.portal.service.jpa.JPALuteceCoreDAO;
import fr.paris.lutece.util.sql.DAOUtil;

public class JWTUserDAO implements IJWTUserDAO {
	
	private static final String SQL_QUERY_SELECT_JWTUSER_BY_USERNAME =  "SELECT * FROM jwt_user WHERE username = ? AND password = PASSWORD(?)";

	@Override
	public boolean checkAuthentication(String username, String password) {
		
		JWTUser jwtUser = new JWTUser( );
		DAOUtil daoUtil = new DAOUtil(SQL_QUERY_SELECT_JWTUSER_BY_USERNAME);
		daoUtil.setString(1,username);
		daoUtil.setString(2,password);
		daoUtil.executeQuery();
		
		if( daoUtil.next() )
		{
			return true;
		} else
		{
			return false;
		}
	}

}
