package fr.paris.lutece.plugins.jwt.util.annotation;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
public @interface RequiresPermissions {

	String resource();
	
	String permission();

}
