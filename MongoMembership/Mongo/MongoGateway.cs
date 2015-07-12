using System;
using System.Collections.Generic;
using System.Linq;
using MongoDB.Bson.Serialization;
using MongoDB.Driver;
using MongoMembership.Utils;
using System.Threading.Tasks;
using MongoDB.Bson;

namespace MongoMembership.Mongo
{
    internal class MongoGateway : IMongoGateway
    {
        private readonly IMongoDatabase _dataBase;
        private IMongoCollection<User> UsersCollection
        {
            get { return _dataBase.GetCollection<User>(typeof(User).Name); }
        }
        private IMongoCollection<Role> RolesCollection
        {
            get { return _dataBase.GetCollection<Role>(typeof(Role).Name); }
        }

        static MongoGateway()
        {
            RegisterClassMapping();
        }

        public MongoGateway(string mongoConnectionString)
        {
            var mongoUrl = new MongoUrl(mongoConnectionString);
            var client = new MongoClient(mongoConnectionString); 
            _dataBase = client.GetDatabase(mongoUrl.DatabaseName);
            CreateIndex();
        }

        public void DropUsers()
        {
            _dataBase.DropCollectionAsync(typeof (User).Name);
        }

        public void DropRoles()
        {
            _dataBase.DropCollectionAsync(typeof(Role).Name);
        }

        #region User
        public void CreateUser(User user)
        {
            if (user.Username != null) user.UsernameLowercase = user.Username.ToLowerInvariant();
            if (user.Email != null) user.EmailLowercase = user.Email.ToLowerInvariant();

            UsersCollection.InsertOneAsync(user);
        }

        public void UpdateUser(User user)
        {
            UsersCollection.UpdateOneAsync(Builders<User>.Filter.Eq(m => m.Id, user.Id), user.ToBsonDocument());    
        }

        public void RemoveUser(User user)
        {
            user.IsDeleted = true;
            UpdateUser(user);
        }

        public async Task<User> GetById(string id)
        {
            var userCount = await UserCount();

            if (id.IsNullOrWhiteSpace() ||userCount == 0)
                return null;

            using (var cursor = await UsersCollection.FindAsync(m => m.Id == id))
            {
                return await cursor.MoveNextAsync() ? cursor.Current.FirstOrDefault() : null;
            }
        }

        public async Task<User> GetByUserName(string applicationName, string username)
        {
            var userCount = await UserCount();


            if (username.IsNullOrWhiteSpace() || userCount == 0)
                return null;
            
            var lowercaseUserName = username.ToLowerInvariant();

            using (var cursor = await UsersCollection.FindAsync(user =>
                user.ApplicationName == applicationName &&
                user.UsernameLowercase == lowercaseUserName &&
                user.IsDeleted == false))
            {
                return await cursor.MoveNextAsync() ? cursor.Current.FirstOrDefault() : null;

            }
        }

        public async Task<User> GetByEmail(string applicationName, string email)
        {
            var userCount = await UserCount();

            if (email.IsNullOrWhiteSpace() || userCount == 0)
                return null;

            var lowercaseEmail = email.ToLowerInvariant();

            using (var cursor = await UsersCollection.FindAsync(user =>
                user.ApplicationName == applicationName &&
                user.EmailLowercase == lowercaseEmail &&
                user.IsDeleted == false))
            {

                return await cursor.MoveNextAsync() ? cursor.Current.FirstOrDefault() : null;

            }


        }

        public async Task<ReturnResult> GetAllByEmail(string applicationName, string email, int pageIndex, int pageSize)
        {
            var userCount = await UserCount();

            if (email.IsNullOrWhiteSpace() || userCount == 0)
            {
                return new ReturnResult {TotalRecords = 0, Users = Enumerable.Empty<User>()};
            }

            var lowercaseEmail = email.ToLowerInvariant();

            using (var cursor = await UsersCollection.FindAsync(user =>
                user.ApplicationName == applicationName &&
                user.EmailLowercase == lowercaseEmail &&
                user.IsDeleted == false,
                new FindOptions<User>()
                {
                    Skip = pageIndex * pageSize,
                    Limit = pageSize
                }))
            {
                var users = new List<User>();
                while (await cursor.MoveNextAsync())
                {
                    users.AddRange(cursor.Current.ToList());
                }
                return new ReturnResult { TotalRecords = users.Count, Users = users };


            }
        }

        public async Task<ReturnResult> GetAllByUserName(string applicationName, string username, int pageIndex, int pageSize)
        {
            var userCount = await UserCount();

            if (username.IsNullOrWhiteSpace() || userCount == 0)
            {
                return new ReturnResult { TotalRecords = 0, Users = Enumerable.Empty<User>() };

            }

            var lowercaseUserName = username.ToLowerInvariant();

             using (var cursor = await UsersCollection.FindAsync(user =>
                user.ApplicationName == applicationName &&
                user.UsernameLowercase == lowercaseUserName &&
                user.IsDeleted == false,
                new FindOptions<User>()
                {
                    Skip = pageIndex * pageSize,
                    Limit = pageSize
                }))
            {
                var users = new List<User>();
                while (await cursor.MoveNextAsync())
                {
                    users.AddRange(cursor.Current.ToList());
                }
                return new ReturnResult { TotalRecords = users.Count, Users = users };


            }
        }

        public async Task<ReturnResult> GetAllAnonymByUserName(string applicationName, string username,int pageIndex, int pageSize)
        {
            var userCount = await UserCount();

            if (username.IsNullOrWhiteSpace() || userCount == 0)
            {
                return new ReturnResult { TotalRecords = 0, Users = Enumerable.Empty<User>() };

            }
            var lowercaseUserName = username.ToLowerInvariant();

            using (var cursor = await UsersCollection.FindAsync(user =>
                user.ApplicationName == applicationName &&
                user.UsernameLowercase == lowercaseUserName &&
                user.IsDeleted == false && 
                user.IsAnonymous,
                new FindOptions<User>()
                {
                    Skip = pageIndex * pageSize,
                    Limit = pageSize
                }))
            {
                var users = new List<User>();
                while (await cursor.MoveNextAsync())
                {
                    users.AddRange(cursor.Current.ToList());
                }
                return new ReturnResult { TotalRecords = users.Count, Users = users };


            }
        }

        public async Task<ReturnResult> GetAll(string applicationName, int pageIndex, int pageSize)
        {
            var userCount = await UserCount();

            if (userCount == 0)
                return new ReturnResult { TotalRecords = 0, Users = Enumerable.Empty<User>() };


            using (var cursor = await UsersCollection.FindAsync(user =>
                user.ApplicationName == applicationName &&
                user.IsDeleted == false,
                new FindOptions<User>()
                {
                    Skip = pageIndex*pageSize,
                    Limit = pageSize
                }))
            {
                var users = new List<User>();
                while (await cursor.MoveNextAsync())
                {
                    users.AddRange(cursor.Current.ToList());
                }
                return new ReturnResult {TotalRecords = users.Count, Users = users};

            }
        }

        public async Task<ReturnResult> GetAllAnonym(string applicationName, int pageIndex, int pageSize)
        {
            var userCount = await UserCount();

            if (userCount == 0)
                return new ReturnResult {TotalRecords = 0, Users = Enumerable.Empty<User>()};

            using (var cursor = await UsersCollection.FindAsync(user =>
                user.ApplicationName == applicationName &&
                user.IsDeleted == false&&
                user.IsAnonymous,
                new FindOptions<User>()
                {
                    Skip = pageIndex * pageSize,
                    Limit = pageSize
                }))
            {
                var users = new List<User>();
                while (await cursor.MoveNextAsync())
                {
                    users.AddRange(cursor.Current.ToList());
                }
                return new ReturnResult { TotalRecords = users.Count, Users = users };

            }


        }

        public async Task<ReturnResult> GetAllInactiveSince(string applicationName, DateTime inactiveDate, int pageIndex, int pageSize)
        {
            var userCount = await UserCount();

            if (userCount == 0)
                return new ReturnResult { TotalRecords = 0, Users = Enumerable.Empty<User>() };

            using (var cursor = await UsersCollection.FindAsync(user =>
                user.ApplicationName == applicationName &&
                user.LastActivityDate <= inactiveDate &&
                user.IsDeleted == false,
                new FindOptions<User>()
                {
                    Skip = pageIndex * pageSize,
                    Limit = pageSize
                }))
            {
                var users = new List<User>();
                while (await cursor.MoveNextAsync())
                {
                    users.AddRange(cursor.Current.ToList());
                }
                return new ReturnResult { TotalRecords = users.Count, Users = users };

            }
        }

        public async Task<ReturnResult>  GetAllInactiveAnonymSince(string applicationName, DateTime inactiveDate, int pageIndex, int pageSize)
        {
            var userCount = await UserCount();

            if (userCount == 0)
                    return new ReturnResult { TotalRecords = 0, Users = Enumerable.Empty<User>() };

            using (var cursor = await UsersCollection.FindAsync(user =>
                user.ApplicationName == applicationName &&
                user.LastActivityDate <= inactiveDate &&
                user.IsAnonymous &&
                user.IsDeleted == false,
                new FindOptions<User>()
                {
                    Skip = pageIndex * pageSize,
                    Limit = pageSize
                }))
            {
                var users = new List<User>();
                while (await cursor.MoveNextAsync())
                {
                    users.AddRange(cursor.Current.ToList());
                }
                return new ReturnResult { TotalRecords = users.Count, Users = users };

            }
        }

        public async Task<ReturnResult> GetInactiveSinceByUserName(string applicationName, string username, DateTime userInactiveSinceDate, int pageIndex, int pageSize)
        {
            var userCount = await UserCount();

            if (userCount == 0)
                return new ReturnResult { TotalRecords = 0, Users = Enumerable.Empty<User>() };

            var lowercaseUserName = username.ToLowerInvariant();

            using (var cursor = await UsersCollection.FindAsync(user =>
               user.ApplicationName == applicationName &&
               user.UsernameLowercase == lowercaseUserName &&
               user.LastActivityDate <= userInactiveSinceDate &&
               user.IsDeleted == false,
               new FindOptions<User>()
               {
                   Skip = pageIndex * pageSize,
                   Limit = pageSize
               }))
            {
                var users = new List<User>();
                while (await cursor.MoveNextAsync())
                {
                    users.AddRange(cursor.Current.ToList());
                }
                return new ReturnResult { TotalRecords = users.Count, Users = users };

            }
        }

        public async Task<ReturnResult> GetInactiveAnonymSinceByUserName(string applicationName, string username, DateTime userInactiveSinceDate, int pageIndex, int pageSize)
        {
            var userCount = await UserCount();

            if (userCount == 0)
                return new ReturnResult { TotalRecords = 0, Users = Enumerable.Empty<User>() };

            var lowercaseUserName = username.ToLowerInvariant();

            using (var cursor = await UsersCollection.FindAsync(user =>
              user.ApplicationName == applicationName &&
              user.UsernameLowercase == lowercaseUserName &&
              user.LastActivityDate <= userInactiveSinceDate &&
              user.IsAnonymous &&
              user.IsDeleted == false,
              new FindOptions<User>()
              {
                  Skip = pageIndex * pageSize,
                  Limit = pageSize
              }))
            {
                var users = new List<User>();
                while (await cursor.MoveNextAsync())
                {
                    users.AddRange(cursor.Current.ToList());
                }
                return new ReturnResult { TotalRecords = users.Count, Users = users };

            }
        }

        public async Task<long> GetUserForPeriodOfTime(string applicationName, TimeSpan timeSpan)
        {
            var timespan = DateTime.UtcNow.Subtract(timeSpan);
            return await 
                UsersCollection.CountAsync(
                    user => user.ApplicationName == applicationName && user.LastActivityDate > timespan);

        }
        #endregion

        #region Role
        public void CreateRole(Role role)
        {
            if (role.RoleName != null) role.RoleNameLowercased = role.RoleName.ToLowerInvariant();

            RolesCollection.InsertOneAsync(role);
        }

        public void RemoveRole(string applicationName, string roleName)
        {
            RolesCollection.DeleteOneAsync(Builders<Role>.Filter.And(
              Builders<Role>.Filter.Eq(Util.GetElementNameFor<Role>(_ => _.ApplicationName), applicationName),
              Builders<Role>.Filter.Eq(Util.GetElementNameFor<Role>(_ => _.RoleNameLowercased), applicationName)
              ));
        }

        public async Task<string[]> GetAllRoles(string applicationName)
        {
            using (var cursor = await RolesCollection.FindAsync(role =>
                role.ApplicationName == applicationName))
            {
                var roles = new List<Role>();
                while (await cursor.MoveNextAsync())
                {
                    roles.AddRange(cursor.Current.ToList());
                }
                return roles.Select(role => role.RoleName).ToArray();

            }
        }

        public async Task<string[]> GetRolesForUser(string applicationName, string username)
        {
            if (username.IsNullOrWhiteSpace())
                return null;

            var user = await GetByUserName(applicationName, username);

            if (user == null || user.Roles == null)
                return null;

            return user.Roles.ToArray();
        }

        public async Task<string[]> GetUsersInRole(string applicationName, string roleName)
        {
            if (roleName.IsNullOrWhiteSpace())
                return null;


            using (var cursor = await UsersCollection.FindAsync(
                Builders<User>.Filter.And(
                Builders<User>.Filter.Eq(m => m.ApplicationName, applicationName),
                Builders<User>.Filter.Or(
                                Builders<User>.Filter.ElemMatch(m => m.Roles, roleName.ToLowerInvariant()),
                                Builders<User>.Filter.ElemMatch(m => m.Roles, roleName)

                ))))
            {
                var users = new List<User>();
                while (await cursor.MoveNextAsync())
                {
                    users.AddRange(cursor.Current.ToList());
                }
                return users.Select(role => role.Username).ToArray();

            }
        }

        public async Task<bool> IsUserInRole(string applicationName, string username, string roleName)
        {
            if (username.IsNullOrWhiteSpace() || roleName.IsNullOrWhiteSpace())
                return false;

            var lowercaseUserName = username.ToLowerInvariant();
            var lowercaseRoleName = roleName.ToLowerInvariant();


            return await UsersCollection.CountAsync(
                Builders<User>.Filter.And(
                    Builders<User>.Filter.Eq(m => m.ApplicationName, applicationName),
                    Builders<User>.Filter.Eq(m => m.UsernameLowercase, lowercaseUserName),
                    Builders<User>.Filter.Or(
                        Builders<User>.Filter.ElemMatch(m => m.Roles, lowercaseRoleName),
                        Builders<User>.Filter.ElemMatch(m => m.Roles, roleName)

                        ))) > 0;
        }

        public async Task<bool> IsRoleExists(string applicationName, string roleName)
        {
            if (roleName.IsNullOrWhiteSpace())
                return false;

            var lowercaseRoleName = roleName.ToLowerInvariant();
            
            return await RolesCollection.CountAsync(role
                        => role.ApplicationName == applicationName
                        && role.RoleNameLowercased == lowercaseRoleName) > 0;
        }

        public async Task<long> UserCount()
        {
           return await UsersCollection.CountAsync(new BsonDocument());
        }

        #endregion

        #region Private Methods
        private static void RegisterClassMapping()
        {
            if (!BsonClassMap.IsClassMapRegistered(typeof(User)))
            {
                // Initialize Mongo Mappings
                BsonClassMap.RegisterClassMap<User>(cm =>
                {
                    cm.AutoMap();
                    cm.SetIgnoreExtraElements(true);
                    cm.SetIsRootClass(true);
                    cm.MapIdField(c => c.Id);
                    cm.MapProperty(c => c.ApplicationName).SetElementName("ApplicationName");
                    cm.MapProperty(c => c.Username).SetElementName("Username");
                    cm.MapProperty(c => c.UsernameLowercase).SetElementName("UsernameLowercase");
                    cm.MapProperty(c => c.Comment).SetElementName("Comment");
                    cm.MapProperty(c => c.CreateDate).SetElementName("CreateDate");
                    cm.MapProperty(c => c.Email).SetElementName("Email");
                    cm.MapProperty(c => c.EmailLowercase).SetElementName("EmailLowercase");
                    cm.MapProperty(c => c.FailedPasswordAnswerAttemptCount).SetElementName("FailedPasswordAnswerAttemptCount");
                    cm.MapProperty(c => c.FailedPasswordAttemptCount).SetElementName("FailedPasswordAttemptCount");
                    cm.MapProperty(c => c.FailedPasswordAnswerAttemptWindowStart).SetElementName("FailedPasswordAnswerAttemptWindowStart");
                    cm.MapProperty(c => c.FailedPasswordAttemptWindowStart).SetElementName("FailedPasswordAttemptWindowStart");
                    cm.MapProperty(c => c.IsApproved).SetElementName("IsApproved");
                    cm.MapProperty(c => c.IsDeleted).SetElementName("IsDeleted");
                    cm.MapProperty(c => c.IsLockedOut).SetElementName("IsLockedOut");
                    cm.MapProperty(c => c.LastActivityDate).SetElementName("LastActivityDate");
                    cm.MapProperty(c => c.LastLockedOutDate).SetElementName("LastLockedOutDate");
                    cm.MapProperty(c => c.LastLoginDate).SetElementName("LastLoginDate");
                    cm.MapProperty(c => c.LastPasswordChangedDate).SetElementName("LastPasswordChangedDate");
                    cm.MapProperty(c => c.Password).SetElementName("Password");
                    cm.MapProperty(c => c.PasswordAnswer).SetElementName("PasswordAnswer");
                    cm.MapProperty(c => c.PasswordQuestion).SetElementName("PasswordQuestion");
                    cm.MapProperty(c => c.PasswordSalt).SetElementName("PasswordSalt");
                    cm.MapProperty(c => c.Roles).SetElementName("Roles").SetIgnoreIfNull(true);
                });
            }

            if (!BsonClassMap.IsClassMapRegistered(typeof(Role)))
            {
                BsonClassMap.RegisterClassMap<Role>(cm =>
                {
                    cm.AutoMap();
                    cm.SetIgnoreExtraElements(true);
                    cm.SetIsRootClass(true);
                    cm.MapProperty(c => c.ApplicationName).SetElementName("ApplicationName");
                    cm.MapProperty(c => c.RoleName).SetElementName("RoleName");
                    cm.MapProperty(c => c.RoleNameLowercased).SetElementName("RoleNameLowercased");
                });
            }
        }

        private void CreateIndex()
        {
            UsersCollection.Indexes.CreateOneAsync(Builders<User>.IndexKeys.Ascending(Util.GetElementNameFor<User>(_ => _.ApplicationName)));

            UsersCollection.Indexes.CreateOneAsync(Builders<User>.IndexKeys.Combine(
                Builders<User>.IndexKeys.Ascending(Util.GetElementNameFor<User>(_ => _.ApplicationName)),
                Builders<User>.IndexKeys.Ascending(Util.GetElementNameFor<User>(_ => _.EmailLowercase))));

            UsersCollection.Indexes.CreateOneAsync(Builders<User>.IndexKeys.Combine(
              Builders<User>.IndexKeys.Ascending(Util.GetElementNameFor<User>(_ => _.ApplicationName)),
              Builders<User>.IndexKeys.Ascending(Util.GetElementNameFor<User>(_ => _.UsernameLowercase))));

            UsersCollection.Indexes.CreateOneAsync(Builders<User>.IndexKeys.Combine(
                Builders<User>.IndexKeys.Ascending(Util.GetElementNameFor<User>(_ => _.ApplicationName)),
                Builders<User>.IndexKeys.Ascending(Util.GetElementNameFor<User>(_ => _.Roles))));


            UsersCollection.Indexes.CreateOneAsync(Builders<User>.IndexKeys.Combine(
                Builders<User>.IndexKeys.Ascending(Util.GetElementNameFor<User>(_ => _.ApplicationName)),
                Builders<User>.IndexKeys.Ascending(Util.GetElementNameFor<User>(_ => _.Roles)),
                Builders<User>.IndexKeys.Ascending(Util.GetElementNameFor<User>(_ => _.UsernameLowercase))));

             UsersCollection.Indexes.CreateOneAsync(Builders<User>.IndexKeys.Combine(
                Builders<User>.IndexKeys.Ascending(Util.GetElementNameFor<User>(_ => _.ApplicationName)),
                Builders<User>.IndexKeys.Ascending(Util.GetElementNameFor<User>(_ => _.IsAnonymous))));


             UsersCollection.Indexes.CreateOneAsync(Builders<User>.IndexKeys.Combine(
                 Builders<User>.IndexKeys.Ascending(Util.GetElementNameFor<User>(_ => _.ApplicationName)),
                 Builders<User>.IndexKeys.Ascending(Util.GetElementNameFor<User>(_ => _.IsAnonymous)),
                 Builders<User>.IndexKeys.Ascending(Util.GetElementNameFor<User>(_ => _.LastActivityDate))));

            UsersCollection.Indexes.CreateOneAsync(Builders<User>.IndexKeys.Combine(
                Builders<User>.IndexKeys.Ascending(Util.GetElementNameFor<User>(_ => _.ApplicationName)),
                Builders<User>.IndexKeys.Ascending(Util.GetElementNameFor<User>(_ => _.IsAnonymous)),
                Builders<User>.IndexKeys.Ascending(Util.GetElementNameFor<User>(_ => _.LastActivityDate)),
                Builders<User>.IndexKeys.Ascending(Util.GetElementNameFor<User>(_ => _.UsernameLowercase))));


            UsersCollection.Indexes.CreateOneAsync(Builders<User>.IndexKeys.Combine(
                Builders<User>.IndexKeys.Ascending(Util.GetElementNameFor<User>(_ => _.ApplicationName)),
                Builders<User>.IndexKeys.Ascending(Util.GetElementNameFor<User>(_ => _.IsAnonymous)),
                Builders<User>.IndexKeys.Ascending(Util.GetElementNameFor<User>(_ => _.UsernameLowercase))));


            UsersCollection.Indexes.CreateOneAsync(Builders<User>.IndexKeys.Combine(
                Builders<User>.IndexKeys.Ascending(Util.GetElementNameFor<User>(_ => _.ApplicationName)),
                Builders<User>.IndexKeys.Ascending(Util.GetElementNameFor<User>(_ => _.UsernameLowercase)),
                Builders<User>.IndexKeys.Ascending(Util.GetElementNameFor<User>(_ => _.IsAnonymous))));


            UsersCollection.Indexes.CreateOneAsync(Builders<User>.IndexKeys.Combine(
                Builders<User>.IndexKeys.Ascending(Util.GetElementNameFor<User>(_ => _.ApplicationName)),
                Builders<User>.IndexKeys.Ascending(Util.GetElementNameFor<User>(_ => _.LastActivityDate))));


            RolesCollection.Indexes.CreateOneAsync(Builders<Role>.IndexKeys.Ascending(Util.GetElementNameFor<Role>(_ => _.ApplicationName)));
            RolesCollection.Indexes.CreateOneAsync(Builders<Role>.IndexKeys.Combine(
               Builders<Role>.IndexKeys.Ascending(Util.GetElementNameFor<Role>(_ => _.ApplicationName)),
               Builders<Role>.IndexKeys.Ascending(Util.GetElementNameFor<Role>(_ => _.RoleNameLowercased))));

        }
        #endregion
    }
}