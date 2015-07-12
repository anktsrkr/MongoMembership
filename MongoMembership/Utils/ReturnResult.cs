using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MongoMembership.Utils
{
   internal class ReturnResult
    {
       public IEnumerable<User> Users { get; set; }
       public long TotalRecords { get; set; }
    }
}
