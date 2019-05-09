/*
 * RESTHeart - the Web API for MongoDB
 * Copyright (C) SoftInstigate Srl
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.restheart.plugins.init;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * Annotation to register an Initializer
 * 
 * @author Andrea Di Cesare <andrea@softinstigate.com>
 */
@Retention(RetentionPolicy.RUNTIME)
public @interface RegisterInitializer {
    /**
     * Defines the name of the initializer that can be used in the configuration
     * file to pass arguments
     */
    String name();
    
    /**
     * Describes the initializer
     */
    String description();

    /**
     * Defines the order of execution (less is higher priority)
     */
    int priority() default 10;
}