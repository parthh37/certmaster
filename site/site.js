// Fills in the Posh-ACME plugin list and points the download buttons at the latest release.
(function () {
  "use strict";

  // Plugins bundled under src/CertMaster.Core/Scripts/PoshAcme/Posh-ACME/Plugins (examples excluded).
  var plugins = [
    "AcmeDns", "Active24", "AddrTools", "Akamai", "Aliyun", "All-Inkl", "Aurora", "AutoDNS", "Azure", "Beget",
    "BlueCat", "Bunny", "ClouDNS", "Cloudflare", "Combell", "Constellix", "CoreNetworks", "DMEasy", "DNSExit",
    "DNSMint", "DNSPod", "DNSimple", "DOcean", "DeSEC", "DomainOffensive", "Domeneshop", "Dreamhost", "DuckDNS",
    "Dynu", "EasyDNS", "Easyname", "EuroDNSReseller", "FreeDNS", "GCloud", "Gandi", "GoDaddy", "GoDaddyV3",
    "GoogleDomains", "Hetzner", "HetznerCloud", "HostUp", "HostingDe", "HostingNL", "HurricaneElectric",
    "HurricaneElectricDyn", "IBMSoftLayer", "INWX", "IONOS", "ISPConfig", "Infoblox", "Infomaniak", "InfomaniakV2",
    "LeaseWeb", "Linode", "Loopia", "LuaDns", "Manual", "MijnHost", "NS1", "NameCom", "NameSilo", "Namecheap",
    "Netcup", "OVH", "OnlineNet", "PointDNS", "Porkbun", "PortsManagement", "PowerDNS", "RFC2136", "Rackspace",
    "Regru", "Route53", "SOLIDServer", "SSHProxy", "Selectel", "SimpleDNSPlus", "Simply", "SimplyCom", "Spaceship",
    "Technitium", "TencentDNS", "TotalUptime", "TransIP", "UKFast", "WEDOS", "WebRoot", "WebSelfHost",
    "WebsupportSK", "Windows", "Yandex", "Zilore", "ZoneEdit", "Zonomi"
  ].sort(function (a, b) { return a.localeCompare(b, "en", { sensitivity: "base" }); });

  var list = document.getElementById("posh-list");
  var filter = document.getElementById("posh-filter");
  var count = document.getElementById("posh-count");
  if (list) {
    var items = plugins.map(function (name) {
      var li = document.createElement("li");
      li.textContent = name;
      list.appendChild(li);
      return li;
    });
    if (count) count.textContent = "(" + plugins.length + ")";
    if (filter) {
      filter.addEventListener("input", function () {
        var q = filter.value.trim().toLowerCase();
        items.forEach(function (li) { li.hidden = q !== "" && li.textContent.toLowerCase().indexOf(q) === -1; });
      });
    }
  }

  // Latest release: link the installers directly when the API answers; otherwise the buttons keep
  // pointing at the releases page.
  var repo = "parthh37/certmaster";
  if (!window.fetch) return;
  fetch("https://api.github.com/repos/" + repo + "/releases/latest", { headers: { Accept: "application/vnd.github+json" } })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (rel) {
      if (!rel || !rel.tag_name) return;
      var assets = rel.assets || [];
      function find(re) {
        for (var i = 0; i < assets.length; i++) if (re.test(assets[i].name)) return assets[i];
        return null;
      }
      var agent = find(/^certmaster-windows-.*\.exe$/i);
      var hub = find(/^certmaster-hub-windows-.*\.exe$/i);
      var a = document.getElementById("dl-agent");
      var h = document.getElementById("dl-hub");
      if (agent && a) { a.href = agent.browser_download_url; a.textContent = "Download CertMaster " + rel.tag_name; }
      if (hub && h) { h.href = hub.browser_download_url; h.textContent = "Download the Hub " + rel.tag_name; }

      var line = document.getElementById("release-line");
      if (line) {
        var when = rel.published_at ? new Date(rel.published_at).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) : "";
        line.textContent = "";
        line.append("Latest: ");
        var link = document.createElement("a");
        link.href = rel.html_url;
        link.textContent = rel.name || rel.tag_name;
        line.append(link);
        if (when) line.append(", released " + when + ".");
      }
    })
    .catch(function () { /* offline or rate-limited: keep the static links */ });
})();
