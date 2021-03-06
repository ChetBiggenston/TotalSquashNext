﻿using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Mvc;
using TotalSquashNext.Models;


namespace TotalSquashNext.Controllers
{
    public class UsersController : Controller
    {
        private PrimarySquashDBContext db = new PrimarySquashDBContext();

            public class SimplerAES
            {
                private static byte[] key = { 123, 217, 19, 11, 24, 26, 85, 45, 114, 184, 27, 162, 37, 112, 222, 209, 241, 24, 175, 144, 173, 53, 196, 29, 24, 26, 17, 218, 131, 236, 53, 209 };
                private static byte[] vector = { 146, 64, 191, 111, 23, 3, 113, 119, 231, 121, 221, 112, 79, 32, 114, 156 };
                private ICryptoTransform encryptor, decryptor;
                private UTF8Encoding encoder;

                public SimplerAES()
                {
                    RijndaelManaged rm = new RijndaelManaged();
                    encryptor = rm.CreateEncryptor(key, vector);
                    encoder = new UTF8Encoding();
                }

                public string Encrypt(string unencrypted)
                {
                    return Convert.ToBase64String(Encrypt(encoder.GetBytes(unencrypted)));
                }

                public byte[] Encrypt(byte[] buffer)
                {
                    return Transform(buffer, encryptor);
                }

                protected byte[] Transform(byte[] buffer, ICryptoTransform transform)
                {
                    MemoryStream stream = new MemoryStream();
                    using (CryptoStream cs = new CryptoStream(stream, transform, CryptoStreamMode.Write))
                    {
                        cs.Write(buffer, 0, buffer.Length);
                    }
                    return stream.ToArray();
                }
            }
        
        
        // GET: Users
        public ActionResult Index()
        {
            var users = db.Users.Include(u => u.AccountType).Include(u => u.Country).Include(u => u.Organization).Include(u => u.Province).Include(u => u.Skill);
            return View(users.ToList());
        }

        // GET: Users/Details/5
        public ActionResult Details(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            User user = db.Users.Find(id);
            if (user == null)
            {
                return HttpNotFound();
            }
            return View(user);
        }

        // GET: Users/Create
        public ActionResult Create()
        {
            ViewBag.accountId = new SelectList(db.AccountTypes, "accountId", "description");
            ViewBag.countryId = new SelectList(db.Countries, "countryId", "countryName");
            ViewBag.organizationId = new SelectList(db.Organizations, "organizationId", "orgName");
            ViewBag.provinceId = new SelectList(db.Provinces, "provinceId", "provinceName");
            ViewBag.skillId = new SelectList(db.Skills, "skillId", "description");
            return View();
        }

        // POST: Users/Create
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create([Bind(Include = "id,username,skillId,password,photo,wins,losses,ties,firstName,lastName,streetAddress,city,provinceId,countryId,phoneNumber,emailAddress,gender,birthDate,accountId,locked,organizationId")] User user)
        {
            SimplerAES ep = new SimplerAES();
            
            if (ModelState.IsValid)
            {
                string tempPass = user.password;
                string encryptedPass = ep.Encrypt(tempPass);
                
                user.password = encryptedPass;
                db.Users.Add(user);
                db.SaveChanges();
                return RedirectToAction("Index");
            }

            ViewBag.accountId = new SelectList(db.AccountTypes, "accountId", "description", user.accountId);
            ViewBag.countryId = new SelectList(db.Countries, "countryId", "countryName", user.countryId);
            ViewBag.organizationId = new SelectList(db.Organizations, "organizationId", "orgName", user.organizationId);
            ViewBag.provinceId = new SelectList(db.Provinces, "provinceId", "provinceName", user.provinceId);
            ViewBag.skillId = new SelectList(db.Skills, "skillId", "description", user.skillId);
            return View(user);
        }

        // GET: Users/Edit/5
        public ActionResult Edit(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            User user = db.Users.Find(id);
            if (user == null)
            {
                return HttpNotFound();
            }
            ViewBag.accountId = new SelectList(db.AccountTypes, "accountId", "description", user.accountId);
            ViewBag.countryId = new SelectList(db.Countries, "countryId", "countryName", user.countryId);
            ViewBag.organizationId = new SelectList(db.Organizations, "organizationId", "orgName", user.organizationId);
            ViewBag.provinceId = new SelectList(db.Provinces, "provinceId", "provinceName", user.provinceId);
            ViewBag.skillId = new SelectList(db.Skills, "skillId", "description", user.skillId);
            return View(user);
        }

        // POST: Users/Edit/5
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit([Bind(Include = "id,username,skillId,password,photo,wins,losses,ties,firstName,lastName,streetAddress,city,provinceId,countryId,phoneNumber,emailAddress,gender,birthDate,accountId,locked,organizationId")] User user)
        {
            if (ModelState.IsValid)
            {
                db.Entry(user).State = EntityState.Modified;
                db.SaveChanges();
                return RedirectToAction("Index");
            }
            ViewBag.accountId = new SelectList(db.AccountTypes, "accountId", "description", user.accountId);
            ViewBag.countryId = new SelectList(db.Countries, "countryId", "countryName", user.countryId);
            ViewBag.organizationId = new SelectList(db.Organizations, "organizationId", "orgName", user.organizationId);
            ViewBag.provinceId = new SelectList(db.Provinces, "provinceId", "provinceName", user.provinceId);
            ViewBag.skillId = new SelectList(db.Skills, "skillId", "description", user.skillId);
            return View(user);
        }

        // GET: Users/Delete/5
        public ActionResult Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            User user = db.Users.Find(id);
            if (user == null)
            {
                return HttpNotFound();
            }
            return View(user);
        }

        // POST: Users/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public ActionResult DeleteConfirmed(int id)
        {
            User user = db.Users.Find(id);
            db.Users.Remove(user);
            db.SaveChanges();
            return RedirectToAction("Index");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
