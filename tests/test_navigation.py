import re,unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
HTML=(ROOT/'app/static/index.html').read_text()
JS=(ROOT/'app/static/app.js').read_text()
STYLE=(ROOT/'app/static/style.css').read_text()
THEME=(ROOT/'app/static/theme.css').read_text()

class NavigationTests(unittest.TestCase):
 def test_header_has_dedicated_health_status_page(self):
  self.assertIn('<a href="#overview-panel">Health Status</a>',HTML)
  self.assertIn("'overview-panel':'Appliance Status'",JS)
  for title in ('Identity','Management network','DNS','Time synchronization','Services and storage','HTTPS and firewall','Active alerts'):
   self.assertIn("healthCard('"+title+"'",JS)
  for control in ('operationsRefresh','applianceReboot','applianceShutdown','operationsStatus'):
   self.assertIn(f'id="{control}"',HTML)
  self.assertIn("api('operations/'+operation",JS)
 def test_service_management_page_is_removed_and_controls_are_distributed(self):
  primary=re.search(r'<nav class="top-navigation"[^>]*>(.*?)</nav>',HTML).group(1)
  self.assertNotIn('Service Management',primary)
  self.assertNotIn('href="#service-panel"',HTML)
  self.assertNotIn('id="service-panel"',HTML)
  self.assertNotIn("'service-panel':",JS)
  for target in ('managementservices','kmipservices','keycloakservices','proxyservices','forwardproxyservices'):
   self.assertIn(f'id="{target}"',HTML)
  self.assertIn("management:'managementservices'",JS)
  self.assertIn("postgres:'keycloakservices'",JS)
  self.assertIn("'configform':['configform','management-service-panel','review-complete']",JS)
  self.assertIn("location.hash='overview-panel'",JS)
 def test_activity_is_embedded_and_scoped_to_one_service(self):
  primary=re.search(r'<nav class="top-navigation"[^>]*>(.*?)</nav>',HTML).group(1)
  self.assertNotIn('Connection Logs',primary)
  self.assertNotIn('id="connection-logs"',HTML)
  self.assertEqual(HTML.count('class="service-activity"'),4)
  for services in ('management','kmip','keycloak,postgres','proxy,forward-proxy'):
   self.assertIn(f'data-activity-services="{services}"',HTML)
  self.assertIn("api('connections?service='+encodeURIComponent(service))",JS)
  self.assertNotIn("'connection-logs':",JS)
 def test_first_setup_dialog_hides_service_activity(self):
  self.assertIn('#setupDialog .service-activity{display:none}',STYLE)
  self.assertEqual(HTML.count('class="service-activity"'),4)
 def test_prepare_appliance_uses_one_page_heading_and_readiness_summary(self):
  self.assertIn("'first-deployment-setup':'Prepare Appliance'",JS)
  self.assertNotIn('Build candidate',HTML)
  self.assertNotIn('<h2>First Deployment Setup</h2>',HTML)
  self.assertIn('class="first-setup-summary"',HTML)
  self.assertIn('id="firstSetupSummary"',HTML)
  self.assertIn('id="wizardRefresh"',HTML)
  self.assertIn('class="first-setup-summary-actions"><span id="firstSetupSummary"',HTML)
  self.assertIn('</span><button id="wizardRefresh" type="button">Refresh status</button></div></div>',HTML)
  self.assertIn('.first-setup-summary-actions{display:flex;align-items:center',STYLE)
  self.assertIn('#wizardRefresh{width:auto;margin:0;padding:7px 11px',STYLE)
  self.assertIn('id="firstSetupCards"',HTML)
  self.assertIn('id="firstSetupCompletion"',HTML)
  self.assertIn("cache:'no-store'",JS)
  self.assertIn("Promise.all([api('services'),api('certificates')])",JS)
  self.assertIn("item.code==='TLS'?Boolean(certificate&&certificate.enrolled)",JS)
 def test_prepare_workflow_synchronizes_primary_navigation_highlight(self):
  self.assertIn('function setActiveNavigation(page)',JS)
  self.assertIn("document.querySelectorAll('.top-navigation a').forEach",JS)
  self.assertIn("document.querySelectorAll('.workflow-nav a').forEach",JS)
  self.assertNotIn('function setActiveNavigation(page){\n setActiveNavigation(page);',JS)
  self.assertIn("setActiveNavigation(item.activePage||'first-deployment-setup')",JS)
  for code,page in (('TLS','first-deployment-setup'),('OIDC','keycloak-panel'),('KMIP','kmip-panel'),('PROXY','proxy-panel'),('EGRESS','proxy-panel')):
   self.assertIn(f"code:'{code}',activePage:'{page}'",JS)
 def test_complete_setup_is_step_five_in_prepare_workflow(self):
  self.assertIn('<p class="nav-title">FIRST DEPLOYMENT STEPS</p>',HTML)
  workflow=re.search(r'<nav aria-label="First Deployment Steps">(.*?)</nav>',HTML).group(1)
  self.assertIn('<a href="#first-deployment-complete"><span>5.</span><strong>Complete setup</strong></a>',workflow)
  self.assertIn('<a class="button-link" href="#keycloak-panel">Next</a></nav></section><section id="first-deployment-complete" class="workflow-step-page" hidden>',HTML)
  self.assertIn("'first-deployment-complete':['first-deployment-complete']",JS)
  self.assertIn("'first-deployment-complete':'Complete Setup'",JS)
  self.assertIn("page==='first-deployment-complete'?'first-deployment-setup':page",JS)
  self.assertNotIn("el('firstSetupCompletion').scrollIntoView",JS)
  self.assertIn("['first-deployment-setup','first-deployment-complete'].includes(requested)",JS)
 def test_each_first_deployment_step_has_bottom_right_navigation(self):
  self.assertEqual(HTML.count('class="workflow-step-actions"'),5)
  expected={
   1:[('keycloak-panel','Next')],
   2:[('first-deployment-setup','Back'),('kmip-panel','Next')],
   3:[('keycloak-panel','Back'),('proxy-panel','Next')],
   4:[('kmip-panel','Back'),('first-deployment-complete','Next')],
   5:[('proxy-panel','Back')],
  }
  for step,links in expected.items():
   panel=re.search(rf'<nav class="workflow-step-actions" aria-label="Step {step} navigation">(.*?)</nav>',HTML).group(1)
   self.assertEqual(re.findall(r'href="#([^"]+)">([^<]+)</a>',panel),links)
  self.assertIn('justify-content:flex-end',STYLE)
  self.assertEqual(HTML.count('workflow-step-page'),5)
  self.assertIn('.workflow-step-page:not([hidden]){display:flex;flex-direction:column;min-height:calc(100vh - 260px)}',STYLE)
  self.assertIn('margin-top:auto',STYLE)
  self.assertIn('.setup-completed .workflow-step-actions{display:none}',STYLE)
 def test_account_menu_has_one_distinct_page_per_link(self):
  panel=re.search(r'<div class="admin-menu-panel">(.*?)</div></details>',HTML).group(1)
  links=re.findall(r'<a href="#([^"]+)">([^<]+)',panel)
  self.assertEqual(links,[('configform','Appliance management'),('certificate-panel','Certificates and trust'),('updates-panel','Appliance updates'),('account-panel','Admin user management'),('change-password-panel','Change password'),('activity-history-panel','Activity history'),('help-panel','Help and runbooks')])
  for target,_ in links:
   self.assertIn("'"+target+"':",JS)
   self.assertRegex(HTML,rf'id="{re.escape(target)}"')
  self.assertIn("'account-panel':'Admin user management'",JS)
  self.assertIn("'change-password-panel':'Change password'",JS)
  self.assertIn("'activity-history-panel':'Activity history'",JS)
  primary=re.search(r'<nav class="top-navigation"[^>]*>(.*?)</nav>',HTML).group(1)
  self.assertNotIn('Administration',primary)
  self.assertNotIn('href="#account-panel"',primary)
 def test_password_and_activity_are_separate_administration_pages(self):
  account=re.search(r'<section aria-label="Administrator accounts" id="account-panel".*?</section></section>',HTML).group(0)
  password=re.search(r'<section aria-label="Change password" id="change-password-panel".*?</section>',HTML).group(0)
  activity=re.search(r'<section aria-label="Activity history" id="activity-history-panel".*?</section>',HTML).group(0)
  self.assertNotIn('id="newpassword"',account)
  self.assertNotIn('id="auditrefresh"',account)
  for control in ('newpassword','repeatpassword','changepassword'):
   self.assertIn(f'id="{control}"',password)
  for control in ('auditrefresh','audit'):
   self.assertIn(f'id="{control}"',activity)
  self.assertIn("if(page==='activity-history-panel')auditHistory()",JS)
  self.assertIn("el('auditrefresh').onclick=auditHistory",JS)
 def test_appliance_management_uses_four_panel_layout(self):
  for title in ('Identity','Timezone','Management network','DNS and time'):
   self.assertRegex(HTML,rf'<h2>{re.escape(title)}</h2>')
  for control in ('timezoneSelect','timezoneSave','networkAcknowledge','configPassword','applyConfiguration','confirm'):
   self.assertIn(f'id="{control}"',HTML)
  self.assertIn('Connection warning',HTML)
  self.assertIn("api('timezone'",JS)
  self.assertIn("api('setup/apply'",JS)
 def test_account_menu_has_dynamic_identity_and_sign_out(self):
  self.assertIn('id="adminUsername">Signed in</strong>',HTML)
  self.assertIn('auth.username',JS)
  self.assertIn('id="logout"',HTML)
  self.assertIn("api('logout',{})",JS)
 def test_administrator_rows_follow_the_active_theme(self):
  self.assertIn('background:var(--raised,#fff);color:var(--text,#1b2a32)',STYLE)
  self.assertIn('background:var(--surface,#fff);color:var(--link,var(--blue));border-color:var(--field-line,#b7ced8)',STYLE)
  self.assertNotIn('.admin-user-item{display:flex;align-items:center;justify-content:space-between;gap:18px;padding:13px 14px;border:1px solid #d8e0e8;border-radius:4px;background:white}',STYLE)
  self.assertIn('style.css?v=1.3',HTML)
  self.assertIn('theme.css?v=1.48',HTML)
  self.assertIn('.admin-user-item{background:var(--raised)!important;color:var(--text)!important;border-color:var(--line)!important}',THEME)
 def test_mattermost_alert_delivery_is_secret_masked_and_testable(self):
  self.assertIn('<option value="mattermost">Mattermost incoming webhook</option>',HTML)
  self.assertIn('id="alertTest"',HTML)
  self.assertIn("r.config.destinationDisplay",JS)
  self.assertIn("operation:'test'",JS)
 def test_build_auto_login_is_visible_and_release_bounded(self):
  self.assertIn('id="buildAuthBanner"',HTML)
  self.assertIn('auth.buildMode',JS)
  firstboot=(ROOT/'provisioning/firstboot.py').read_text()
  self.assertIn("(ROOT/'build-auth-bypass').unlink",firstboot)
  self.assertIn("(DATA/'management/build-auth-bypass.json').unlink",firstboot)
  seal=(ROOT/'provisioning/seal_release.sh').read_text()
  self.assertIn('/etc/security-appliance/build-auth-bypass',seal)
  self.assertIn('/var/lib/security-appliance/management/build-auth-bypass.json',seal)
  self.assertIn("grep -qx 'SECURITY_BUILD_AUTH_BYPASS=1'",seal)
  self.assertIn('verify standard login before sealing',seal)
  release=(ROOT/'deployment/Create-SealedReleaseCandidate.ps1').read_text()
  self.assertIn('[switch]$StandardLoginVerified',release)
  self.assertIn("if(-not $StandardLoginVerified)",release)
 def test_change_authorization_is_requested_only_when_action_is_selected(self):
  self.assertNotIn('admin-authorization',HTML)
  self.assertNotIn('id="reauth"',HTML)
  self.assertNotIn("el('reauth')",JS)
  self.assertIn('function requestAdminPassword(action)',JS)
  for action in ('certcsr','certdiscard','certimport','changepassword','createAdmin','forwardProxyForm'):
   self.assertIn("el('"+action+"')",JS)
 def test_labis_service_page_structure_is_used_for_security_services(self):
  self.assertEqual(HTML.count('class="appliance-card workflow-step-page labis-service-page"'),3)
  self.assertEqual(HTML.count('class="labis-service-control"'),3)
  for marker in ('11 / LAB SECURITY','Keycloak / OIDC Management','12 / LAB SECURITY','Proxy Management','13 / LAB SECURITY','KMIP Key Management'):
   self.assertIn(marker,HTML)
  self.assertIn('class="labis-configuration-grid"',HTML)
  self.assertEqual(HTML.count('class="labis-how-to-use"'),2)
  self.assertEqual(HTML.count('class="labis-optional-panel"'),3)
  self.assertIn('body.service-page-active .page-header{display:none}',STYLE)
  self.assertIn("const serviceWorkspacePages=['kmip-panel','keycloak-panel','proxy-panel'];",JS)
  self.assertIn("updateServicePageStatus('keycloakPageStatus'",JS)
 def test_clean_first_boot_does_not_require_an_existing_proxy_container(self):
  runtime=(ROOT/'provisioning/compose_runtime.py').read_text()
  self.assertIn("proxy_state=subprocess.run",runtime)
  self.assertIn("proxy_state.returncode==0 and proxy_state.stdout.strip()=='true'",runtime)
if __name__=='__main__':unittest.main()
