/*-
 * ========================LICENSE_START=================================
 * restheart-security
 * %%
 * Copyright (C) 2018 - 2020 SoftInstigate
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * =========================LICENSE_END==================================
 */
package org.restheart.mongodb.security;

import org.restheart.plugins.MongoInterceptor;
import org.restheart.plugins.RegisterPlugin;
import org.restheart.security.MongoPermissions;
import org.restheart.utils.HttpStatus;

import java.util.Deque;
import java.util.Map;
import java.util.Set;

import org.restheart.exchange.MongoRequest;
import org.restheart.exchange.MongoResponse;
import org.restheart.plugins.InterceptPoint;

@RegisterPlugin(name = "mongoPermissionForbidQueryParams",
    description = "Forbids query parameters according to the mongo.forbidQueryParams ACL permission",
    interceptPoint = InterceptPoint.REQUEST_AFTER_AUTH,
    enabledByDefault = true,
    priority = 10)
public class ForbidQueryParams implements MongoInterceptor {

    @Override
    public void handle(MongoRequest request, MongoResponse response) throws Exception {
        var forbidQueryParams = MongoPermissions.of(request).getForbidQueryParams();

        if (contains(request.getQueryParameters(), forbidQueryParams)) {
                response.setStatusCode(HttpStatus.SC_FORBIDDEN);
                request.setInError(true);
        }
    }

    private boolean contains(Map<String, Deque<String>> queryParams, Set<String>  forbidQueryParams) {
        return queryParams != null
            && queryParams.keySet().stream().anyMatch(qp -> forbidQueryParams.contains(qp));
    }

    @Override
    public boolean resolve(MongoRequest request, MongoResponse response) {
        if (!request.isHandledBy("mongo")
            || request.getQueryParameters() == null
            || request.getQueryParameters().isEmpty()) {
            return false;
        }

        var mongoPermission = MongoPermissions.of(request);

        if (mongoPermission != null) {
            return !mongoPermission.getForbidQueryParams().isEmpty();
        } else {
            return false;
        }
    }
}
