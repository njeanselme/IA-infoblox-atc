/*
 asa_init.js
 '''
 Written by Kyle Smith for Aplura, LLC
 Copyright (C) 2016 Aplura, ,LLC

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either version 2
 of the License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 '''
 */
require([
    "jquery",
    "asa_config",
    "splunkjs/ready!",
    "splunkjs/mvc/simplexml/ready!" ,
   "asa_mi_infoblox", 
 "asa_proxy", 
 "asa_credential", 
 "asa_readme"
], function ($,
             configManager,
             mvc,
             ignored , 
    asa_mi_infoblox,
    asa_proxy,
    asa_credential,
    asa_readme
) {
    var configMan = new configManager();
    
 var miMan = new asa_mi_infoblox();
    var appConfig_asa_proxy = new asa_proxy(); 
    var appConfig_asa_credential = new asa_credential(); 
//    var appConfig_asa_readme = new asa_readme(); 



    var tryfunc = function() {
    if (!$(".clickable_mod_input.enablement a, .clickable.delete a").size()) {
      window.requestAnimationFrame(tryfunc);
    }else {
      $(".clickable_mod_input.enablement a, .clickable.delete a").tooltip({position: {collision: "flip"}});
     }
  };
    tryfunc();
});