package fr.paris.lutece.plugins.jwt.business.entities;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "jwt_user")
public class JWTUser implements Serializable
{
	
	/**
	 * The jwt user id
	 */
	private int _id;
	
	/**
	 * the jwt username
	 */
	private String _username;
	
	/**
	 * password of user
	 */
	private String _password;
	
    @Id
    @GeneratedValue(strategy=GenerationType.AUTO)
    @Column(name = "id", unique = true, nullable = false)
	public int getId() {
		return _id;
	}

	public void setId(int _id) {
		this._id = _id;
	}

	@Column(name = "username")
	public String getUsername() {
		return _username;
	}

	public void setUsername(String _username) {
		this._username = _username;
	}

	@Column(name = "password")
	public String getPassword() {
		return _password;
	}

	public void setPassword(String _password) {
		this._password = _password;
	}

}
