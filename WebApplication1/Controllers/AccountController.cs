using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security;
using WebApplication1.Models;

namespace WebApplication1.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        public AccountController() : this(IdentityConfig.Secrets, IdentityConfig.Logins, IdentityConfig.Users, IdentityConfig.Roles, IdentityConfig.ExternalIdentityHandler) { }

        public AccountController(IUserSecretStore secrets, IUserLoginStore logins, IUserStore users, IRoleStore roles, ISecureDataHandler<ClaimsIdentity> externalIdentityHandler)
        {
            Secrets = secrets;
            Logins = logins;
            Users = users;
            Roles = roles;
            ExternalIdentityHandler = externalIdentityHandler;
        }

        public IUserSecretStore Secrets { get; private set; }
        public IUserLoginStore Logins { get; private set; }
        public IUserStore Users { get; private set; }
        public IRoleStore Roles { get; private set; }
        public ISecureDataHandler<ClaimsIdentity> ExternalIdentityHandler { get; private set; }

        //
        // POST: /Account/Disassociate
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Disassociate(string loginProvider, string providerKey)
        {
            ManageMessageId? message = null;
            string userId = User.Identity.GetUserId();
            if (await UnlinkAccountForUser(userId, loginProvider, providerKey))
            {
                // If you remove a local account, need to delete the login as well
                if (loginProvider == IdentityConfig.LocalLoginProvider)
                {
                    await Secrets.Delete(providerKey);
                }
                message = ManageMessageId.RemoveLoginSuccess;
            }

            return RedirectToAction("Manage", new { Message = message });
        }

        //
        // GET: /Account/Manage
        public async Task<ActionResult> Manage(ManageMessageId? message)
        {
            ViewBag.StatusMessage =
                message == ManageMessageId.ChangePasswordSuccess ? "Your password has been changed."
                : message == ManageMessageId.SetPasswordSuccess ? "Your password has been set."
                : message == ManageMessageId.RemoveLoginSuccess ? "The external login was removed."
                : message == ManageMessageId.AddLoginSuccess ? "The external login was added."
                : String.Empty;
            string localUserName = await Logins.GetProviderKey(User.Identity.GetUserId(), IdentityConfig.LocalLoginProvider);
            ViewBag.HasLocalPassword = localUserName != null;
            ViewBag.UserName = localUserName;
            return View();
        }

        //
        // POST: /Account/Manage
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Manage(ManageUserViewModel model)
        {
            string userId = User.Identity.GetUserId();
            string localUserName = await Logins.GetProviderKey(User.Identity.GetUserId(), IdentityConfig.LocalLoginProvider);
            bool hasLocalAccount = localUserName != null;
            ViewBag.HasLocalPassword = hasLocalAccount;
            if (hasLocalAccount)
            {
                if (ModelState.IsValid)
                {
                    bool changePasswordSucceeded = await ChangePassword(localUserName, model.OldPassword, model.NewPassword);
                    if (changePasswordSucceeded)
                    {
                        return RedirectToAction("Manage", new { Message = ManageMessageId.ChangePasswordSuccess });
                    }
                    else
                    {
                        ModelState.AddModelError(String.Empty, "The current password is incorrect or the new password is invalid.");
                    }
                }
            }
            else
            {
                // User does not have a local password so remove any validation errors caused by a missing OldPassword field
                ModelState state = ModelState["OldPassword"];
                if (state != null)
                {
                    state.Errors.Clear();
                }

                if (ModelState.IsValid)
                {
                    try
                    {
                        // Create the local login info and link the local account to the user
                        localUserName = User.Identity.GetUserName();
                        if (await Secrets.Create(new UserSecret(localUserName, model.NewPassword)) &&
                            await Logins.Add(new UserLogin(userId, IdentityConfig.LocalLoginProvider, localUserName)))
                        {
                            return RedirectToAction("Manage", new { Message = ManageMessageId.SetPasswordSuccess });
                        }
                        else
                        {
                            ModelState.AddModelError(String.Empty, "Failed to set password");
                        }
                    }
                    catch (Exception e)
                    {
                        ModelState.AddModelError(String.Empty, e);
                    }
                }
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // POST: /Account/ExternalLogin
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string provider)
        {
            return new ChallengeResult(provider, Url.Action("ExternalLoginCallback", "Account"));
        }

        //
        // GET: /Account/ExternalLoginCallback
        [AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback()
        {
            ClaimsIdentity id = await GetExternalIdentity();

            if (id == null)
            {
                return View("ExternalLoginFailure");
            }

            Claim providerKeyClaim = id.FindFirst(ClaimTypes.NameIdentifier);
            if (providerKeyClaim == null || providerKeyClaim.Issuer == null)
            {
                return View("ExternalLoginFailure");
            }

            string loginProvider = providerKeyClaim.Issuer;
            string providerKey = providerKeyClaim.Value;
            string userId = await Logins.GetUserId(loginProvider, providerKey);

            if (!String.IsNullOrEmpty(userId))
            {
                return View("ExternalLoginFailure");
            }

            if (!User.Identity.IsAuthenticated)
            {
                return View("ExternalLoginFailure");
            }

            // The current user is logged in, just add the new account
            await Logins.Add(new UserLogin(User.Identity.GetUserId(), loginProvider, providerKey));

            return RedirectToAction("Manage", new { Message = ManageMessageId.AddLoginSuccess });
        }

        //
        // POST: /Account/LogOff
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            HttpContext.SignOut();

            return RedirectToAction("Index", "Home", new { logoff = true });
        }

        [AllowAnonymous]
        [ChildActionOnly]
        public ActionResult ExternalLoginsList()
        {
            return (ActionResult)PartialView("_ExternalLoginsListPartial", new List<AuthenticationDescription>(HttpContext.GetExternalAuthenticationTypes()));
        }

        [ChildActionOnly]
        public ActionResult RemoveAccountList()
        {
            return Task.Run(async () =>
            {
                var linkedAccounts = await Logins.GetLogins(User.Identity.GetUserId());
                ViewBag.ShowRemoveButton = linkedAccounts.Count > 1;
                return (ActionResult)PartialView("_RemoveAccountPartial", linkedAccounts);
            }).Result;
        }

        #region Helpers

        private async Task<bool> UnlinkAccountForUser(string userId, string loginProvider, string providerKey)
        {
            string ownerAccount = await Logins.GetUserId(loginProvider, providerKey);
            if (ownerAccount == userId)
            {
                if ((await Logins.GetLogins(userId)).Count > 1)
                {
                    await Logins.Remove(userId, loginProvider, providerKey);
                    return true;
                }
            }
            return false;
        }

        private async Task<bool> ChangePassword(string userName, string oldPassword, string newPassword)
        {
            bool changePasswordSucceeded = false;
            if (await Secrets.Validate(userName, oldPassword))
            {
                changePasswordSucceeded = await Secrets.UpdateSecret(userName, newPassword);
            }
            return changePasswordSucceeded;
        }

        private Task<ClaimsIdentity> GetExternalIdentity()
        {
            return IdentityConfig.GetExternalIdentity(HttpContext);
        }

        private class ChallengeResult : HttpUnauthorizedResult
        {
            public ChallengeResult(string provider, string redirectUrl)
            {
                LoginProvider = provider;
                RedirectUrl = redirectUrl;
            }

            public string LoginProvider { get; set; }
            public string RedirectUrl { get; set; }

            public override void ExecuteResult(ControllerContext context)
            {
                context.HttpContext.Challenge(LoginProvider, new AuthenticationExtra
                {
                    RedirectUrl = RedirectUrl
                });
            }
        }

        public enum ManageMessageId
        {
            ChangePasswordSuccess,
            SetPasswordSuccess,
            RemoveLoginSuccess,
            AddLoginSuccess
        }

        #endregion
    }
}
