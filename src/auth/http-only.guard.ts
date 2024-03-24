import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';


@Injectable()
export class HttpOnlyGuard implements CanActivate {
    // This method will be called by the NestJS framework to determine if the user has access to the route
    canActivate(context: ExecutionContext): boolean {
            // Get the request object
            const request = context.switchToHttp().getRequest();
            // Check if the cookie is present
            if (request.cookies && 'token' in request.cookies && request.cookies.token.length > 0) {
            // The cookie is present
            return true;
        }
        // The cookie is not present, deny access
        return false;
    }
}