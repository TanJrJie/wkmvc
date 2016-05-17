using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Service.IService
{
    public interface IUserManage:IRepository<Domain.Gy_User>
    {
        Domain.Gy_User UserLogin(string account,string password);

        bool IsAdmin(int userId);

        string GetUserName(string UserId);
    }
}
