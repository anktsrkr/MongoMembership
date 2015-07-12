using System;
using System.Collections.Specialized;
using System.Configuration;
using System.Configuration.Provider;
using System.Linq;
using System.Web.Hosting;
using System.Web.Security;
using MongoMembership.Mongo;
using MongoMembership.Utils;

namespace MongoMembership.Providers
{
    public class MongoRoleProvider : RoleProvider
    {
        internal string MongoConnectionString { get; private set; }
        private IMongoGateway _mongoGateway;

        public override string ApplicationName { get; set; }

        public override void Initialize(string name, NameValueCollection config)
        {
            this.ApplicationName = Util.GetValue(config["applicationName"], HostingEnvironment.ApplicationVirtualPath);

            this.MongoConnectionString = Util.GetConnectionStringByName(Util.GetValue(config["connectionStringKeys"], string.Empty));
            this._mongoGateway = new MongoGateway(MongoConnectionString);

            base.Initialize(name, config);
        }

        public override void AddUsersToRoles(string[] usernames, string[] roleNames)
        {
            foreach (var roleName in roleNames.Where(roleName => !RoleExists(roleName)))
                CreateRole(roleName);

            foreach (var username in usernames)
            {
                var user = this._mongoGateway.GetByUserName(this.ApplicationName, username).Result;

                if (user == null)
                    throw new ProviderException("The user '{0}' was not found.".F(username));

                var username1 = username; //Closure solving
                foreach (var roleName in roleNames.Where(roleName => !IsUserInRole(username1, roleName)))
                {
                    user.Roles.Add(roleName.ToLowerInvariant());
                    this._mongoGateway.UpdateUser(user);
                }
            }
        }

        public override void CreateRole(string roleName)
        {
            if (RoleExists(roleName))
                return;

            var role = new Role
            {
                ApplicationName = this.ApplicationName,
                RoleName = roleName,
                RoleNameLowercased = roleName.ToLowerInvariant()
            };

            this._mongoGateway.CreateRole(role);
        }

        public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
        {
            if (!RoleExists(roleName))
                return false;

            var users = GetUsersInRole(roleName);

            if (throwOnPopulatedRole && users.Length > 0)
                throw new ProviderException("This role cannot be deleted because there are users present in it.");

            RemoveUsersFromRoles(users, new[] { roleName });
            this._mongoGateway.RemoveRole(this.ApplicationName, roleName);
            return true;
        }

        public override string[] FindUsersInRole(string roleName, string usernameToMatch)
        {
            if (!RoleExists(roleName))
                return null;

            return this._mongoGateway.GetUsersInRole(this.ApplicationName, roleName).Result;
        }

        public override string[] GetAllRoles()
        {
            return this._mongoGateway.GetAllRoles(this.ApplicationName).Result;
        }

        public override string[] GetRolesForUser(string username)
        {
            return this._mongoGateway.GetRolesForUser(this.ApplicationName, username).Result;
        }

        public override string[] GetUsersInRole(string roleName)
        {
            return this._mongoGateway.GetUsersInRole(this.ApplicationName, roleName).Result;
        }

        public override bool IsUserInRole(string username, string roleName)
        {
            return this._mongoGateway.IsUserInRole(this.ApplicationName, username, roleName).Result;
        }

        public override void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
        {
            foreach (var username in usernames)
            {
                foreach (var roleName in roleNames)
                {
                    if (!IsUserInRole(username, roleName)) continue;

                    var user = this._mongoGateway.GetByUserName(this.ApplicationName, username).Result;
                    user.Roles.Remove(roleName.ToLowerInvariant());
                    this._mongoGateway.UpdateUser(user);
                }
            }
        }

        public override bool RoleExists(string roleName)
        {
            return this._mongoGateway.IsRoleExists(this.ApplicationName, roleName).Result;
        }
    }
}
