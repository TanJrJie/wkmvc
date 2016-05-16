using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Domain;
using Service.IService;
using Service.ServiceImp;
using Common;

namespace WebPage.Areas.SysManage.Controllers
{
    public class AccountController : Controller
    {
        #region 声明容器
        IUserManage UserManage { get; set; }
        #endregion

        #region 基本视图
        public ActionResult Index()
        {
            return View();
        }
        #endregion

        #region 帮助方法
        #endregion

        /// <summary>
        /// 登录验证
        /// add yuangang by 2016-05-16
        /// </summary>
        [ValidateAntiForgeryToken]
        public ActionResult Login(Domain.Gy_User item)
        {
            var json = new Common.JsonHelper.JsonHelper() { Msg = "登录成功", Status = "n" };
            try
            {
                //调用登录验证接口 返回用户实体类
                var users = UserManage.UserLogin(item.UserCode.Trim(), item.PassWord.Trim());
                if (users != null)
                {
                    json.Status = "y";
                }
                else
                {
                    json.Msg = "用户名或密码不正确";
                }

            }
            catch (Exception e)
            {
                json.Msg = e.Message;
            }
            return Json(json, JsonRequestBehavior.AllowGet);
        }
    }
}