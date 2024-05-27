<script type='text/javascript' src='modules/certman/assets/js/views/regions.js?123'></script>
<?php
if (!empty($message)) {
    $messagehtml = '<div class="alert alert-' . $message['type'] . '">' . $message['message'] . '</div>';
}

$alert = "<div class='alert alert-info'><h3>" . _("Important") . "</h3>";
$alert .= "<p>" . _("Let's Encrypt certificate creation and validation requires unrestricted inbound http access on port 80 to the Let's Encrypt token directories") . " </p>";
$alert .= "<p>" . _("If security is managed by the PBX Firewall module, this process should be automatic. Alternate security methods and external firewalls will require manual configuration.") . " </p>";
$alert .= "<p>" . _("For more information see: ") . "<a href='https://wiki.sangoma.com/display/FPG/Certificate+Management+User+Guide' target='_blank'>https://wiki.sangoma.com/display/FPG/Certificate+Management+User+Guide</a> </p>";
$alert .= "</div>";
?>

<div class="container-fluid">
    <h1><?php echo !empty($cert['cid']) ? _("Edit Let's Encrypt Certificate") : _("New Let's Encrypt Certificate") ?></h1>
    <?php echo !empty($messagehtml) ? $messagehtml : "" ?>
    <div class='alert alert-info'><?php echo $alert; printf(_("Let's Encrypt Certificates are <strong>automatically</strong> updated by %s when required (Approximately every 2 months). Do not install your own certificate updaters!"), FreePBX::Config()->get("DASHBOARD_FREEPBX_BRAND")); ?></div>
    <div class="display full-border">
        <div class="row">
            <div class="col-sm-12">
                <div class="fpbx-container">
                    <div class="display full-border" id='certpage'>
                        <form class="fpbx-submit" name="frm_certman" action="config.php?display=certman" method="post" enctype="multipart/form-data" data-fpbx-delete="config.php?display=certman&amp;certaction=delete&amp;t=cert&amp;id=<?php echo $cert['cid'] ?>">
                            <input id="certaction" type="hidden" name="certaction" value="<?php echo !empty($cert['cid']) ? 'edit' : 'add' ?>">
                            <input id="certtype" type="hidden" name="type" value="le">
                            <input id="cid" type="hidden" name="cid" value="<?php echo !empty($cert['cid']) ? $cert['cid'] : '' ?>">

                            <!-- Begin Section -->
                            <div class="section-title" data-for="edit-cert">
                                <h3>
                                    <i class="fa fa-minus"></i>
                                    <?php echo !empty($cert['cid']) ? _("Edit Certificate") : _("New Certificate") ?>
                                </h3>
                            </div>
                            <div class="section" data-id="edit-cert">
                                <div class="element-container">
                                    <div class="row">
                                        <div class="form-group form-horizontal">
                                            <div class="col-md-3">
                                                <label class="control-label" for="host"><?php echo _("Certificate Host Name") ?></label>
                                                <i class="fa fa-question-circle fpbx-help-icon" data-for="host"></i>
                                            </div>
                                            <div class="col-md-9">
                                                <?php if (empty($cert['cid'])) { ?>
                                                    <input type="text" class="form-control" id="host" name="host" placeholder="server.example.com" required value="<?php echo $hostname ?>">
                                                <?php } else { ?>
                                                    <?php echo !empty($cert['basename']) ? $cert['basename'] : "" ?>
                                                <?php } ?>
                                            </div>
                                        </div>
                                        <div class="col-md-12">
                                            <span id="host-help" class="help-block fpbx-help-block" style=""><?php echo _("This must be the hostname you are requesting a certificate for. LetsEncrypt will validate that the hostname resolves to this machine, and attempt to connect to it.") ?></span>
                                        </div>
                                    </div>
                                </div>
                                <div class="element-container">
                                    <div class="row">
                                        <div class="form-group form-horizontal">
                                            <div class="col-md-3">
                                                <label class="control-label" for="email"><?php echo _("Owners Email") ?></label>
                                                <i class="fa fa-question-circle fpbx-help-icon" data-for="email"></i>
                                            </div>
                                            <div class="col-md-9">
                                                <input type="text" class="form-control" id="email" name="email" placeholder="you@example.com" required value="<?php echo $cert['additional']['email'] ?>">
                                            </div>
                                        </div>
                                        <div class="col-md-12">
                                            <span id="email-help" class="help-block fpbx-help-block" style=""><?php echo _("This email address is given to Let's Encrypt. It may be used by them if the certificate is approaching expiration and it has not been renewed.") ?></span>
                                        </div>
                                    </div>
                                </div>

                                <div class="element-container">
                                    <div class="row">
                                        <div class="form-group form-horizontal">
                                            <div class="col-md-3">
                                                <label class="control-label" for="C"><?php echo _("Country") ?></label>
                                            </div>
                                            <div class="col-md-9">
                                                <?php
                                                $country = !empty($cert['additional']['C']) ? $cert['additional']['C'] : "CA";
                                                $state = !empty($cert['additional']['ST']) ? $cert['additional']['ST'] : "Ontario";
                                                ?>
                                                <select class="form-control" id="C" name="C" data-current="<?php echo $country; ?>" disabled> </select>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div class="element-container">
                                    <div class="row">
                                        <div class="form-group form-horizontal">
                                            <div class="col-md-3">
                                                <label class="control-label" for="st"><?php echo _("State/Province/Region") ?></label>
                                            </div>
                                            <div class="col-md-9">
                                                <select class="form-control" id="ST" name="ST" data-current="<?php echo $state; ?>"> </select>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <!-- Alternative Names -->
                                <div class="element-container">
                                    <div class="row">
                                        <div class="form-group form-horizontal">
                                            <div class="col-md-3">
                                                <label class="control-label" for="SAN"><?php echo _("Alternative Names"); ?></label>
                                                <i class="fa fa-question-circle fpbx-help-icon" data-for="SAN"></i>
                                            </div>
                                            <div class="col-md-9">
                                                <textarea id="SAN" name="SAN" class="form-control" cols=50 rows=2><?php echo isset($cert['additional']['san']) ? implode("\n", $cert['additional']['san']) : ""; ?></textarea>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="row">
                                        <div class="col-md-12">
                                            <span id="SAN-help" class="help-block fpbx-help-block"><?php echo _("List alternate Fully Qualified Domain Names for this certificate, one per line. Names must be resolvable by public DNS and point to this server.") ?></span>
                                        </div>
                                    </div>
                                </div>

                                <!-- Challenge Method -->
                                <div class="element-container">
                                    <div class="row">
                                        <div class="form-group form-horizontal">
                                            <div class="col-md-3">
                                                <label class="control-label" for="challengetype"><?php echo _("Challenge Over") ?></label>
                                                <i class="fa fa-question-circle fpbx-help-icon" data-for="challengetype"></i>
                                            </div>
                                            <div class="col-md-9">
                                                <select class="form-control" id="challengetype" name="challengetype" required>
                                                    <option value="http" <?php echo ($cert['additional']['challengetype'] === 'http') ? "selected" : ""; ?>>HTTP (Port 80)</option>
                                                    <option value="dns" <?php echo ($cert['additional']['challengetype'] === 'dns') ? "selected" : ""; ?>>DNS</option>
                                                </select>
                                            </div>
                                        </div>
                                        <div class="col-md-12">
                                            <span id="challengetype-help" class="help-block fpbx-help-block"><?php echo _("Choose the challenge method for Let's Encrypt certificate validation.") ?></span>
                                        </div>
                                    </div>
                                </div>
                                <!-- END Challenge Method -->

                                <!-- DNS Provider -->
                                <div class="element-container" id="dns-provider-container" style="display: none;">
                                    <div class="row">
                                        <div class="form-group form-horizontal">
                                            <div class="col-md-3">
                                                <label class="control-label" for="dnsprovider"><?php echo _("DNS Provider") ?></label>
                                                <i class="fa fa-question-circle fpbx-help-icon" data-for="dnsprovider"></i>
                                            </div>
                                            <div class="col-md-9">
                                                <select class="form-control" id="dnsprovider" name="dnsprovider">
                                                    <option value="cloudflare" <?php echo ($cert['additional']['dnsprovider'] === 'cloudflare') ? "selected" : ""; ?>>Cloudflare</option>
                                                    <!-- Add other DNS providers here -->
                                                </select>
                                            </div>
                                        </div>
                                        <div class="col-md-12">
                                            <span id="dnsprovider-help" class="help-block fpbx-help-block"><?php echo _("Select your DNS provider for DNS challenge validation.") ?></span>
                                        </div>
                                    </div>
                                </div>
                                <!-- END DNS Provider -->

                                <!-- DNS Credentials -->
                                <div class="element-container" id="dns-credentials-container" style="display: none;">
                                    <div class="row">
                                        <div class="form-group form-horizontal">
                                            <div class="col-md-3">
                                                <label class="control-label" for="dnscredentials"><?php echo _("DNS Credentials") ?></label>
                                                <i class="fa fa-question-circle fpbx-help-icon" data-for="dnscredentials"></i>
                                            </div>
                                            <div class="col-md-9">
                                                <textarea id="dnscredentials" name="dnscredentials" class="form-control" cols=50 rows=2><?php echo $cert['additional']['dnscredentials']; ?></textarea>
                                            </div>
                                        </div>
                                        <div class="col-md-12">
                                            <span id="dnscredentials-help" class="help-block fpbx-help-block"><?php echo _("Provide your DNS provider credentials for DNS challenge validation.") ?></span>
                                        </div>
                                    </div>
                                </div>
                                <!-- END DNS Credentials -->

                                <!-- Remove DST Root CA X3 -->
                                <div class="element-container">
                                    <div class="row">
                                        <div class="form-group form-horizontal">
                                            <div class="col-md-3">
                                                <label class="control-label" for="removeDstRootCaX3"><?php echo _("Remove DST Root CA X3") ?></label>
                                                <i class="fa fa-question-circle fpbx-help-icon" data-for="removeDstRootCaX3"></i>
                                            </div>
                                            <div class="col-md-9">
                                                <input type="checkbox" id="removeDstRootCaX3" name="removeDstRootCaX3" <?php echo ($cert['additional']['removeDstRootCaX3'] ? "checked" : ""); ?>>
                                            </div>
                                        </div>
                                        <div class="col-md-12">
                                            <span id="removeDstRootCaX3-help" class="help-block fpbx-help-block"><?php echo _("The Let's Encrypt bundled 'DST Root CA X3' can cause issues with older clients. This option removes the 'DST Root CA X3' from the certificate bundle.") ?></span>
                                        </div>
                                    </div>
                                </div>
                                <!-- END DST Root CA X3 -->
                            </div>
                            <!-- END Section -->

                            <!-- Begin Section -->
                            <?php if (!empty($cert['cid'])) { ?>
                                <div class="section-title" data-for="show-cert">
                                    <h3>
                                        <i class="fa fa-minus"></i>
                                        <?php echo _("Issued Certificate Details") ?>
                                    </h3>
                                </div>
                                <div class="section" data-id="show-cert">
                                    <!-- Common Name -->
                                    <div class="element-container">
                                        <div class="row">
                                            <div class="form-group form-horizontal">
                                                <div class="col-md-3">
                                                    <label class="control-label" for="cn"><?php echo _("Certificate Common Name") ?></label>
                                                </div>
                                                <div class="col-md-9"><?php echo $certinfo['subject']['CN'] ?></div>
                                            </div>
                                        </div>
                                    </div>
                                    <!-- END Common Name -->

                                    <!-- Alternative Names -->
                                    <div class="element-container">
                                        <div class="row">
                                            <div class="form-group form-horizontal">
                                                <div class="col-md-3">
                                                    <label class="control-label" for="an"><?php echo _("Certificate Alternative Names") ?></label>
                                                </div>
                                                <div class="col-md-9">
                                                    <?php echo $certinfo['extensions']['subjectAltName'] ?>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    <!-- END Alternative Names -->

                                    <!-- Expiration -->
                                    <div class="element-container">
                                        <div class="row">
                                            <div class="form-group form-horizontal">
                                                <div class="col-md-3">
                                                    <label class="control-label" for="expires"><?php echo _("Certificate Valid Until") ?></label>
                                                </div>
                                                <div class="col-md-9"> <?php echo FreePBX::Certman()->getReadableExpiration($certinfo['validTo_time_t']); ?> </div>
                                            </div>
                                        </div>
                                    </div>
                                    <!-- END Expiration -->

                                    <!-- Policies -->
                                    <div class="element-container">
                                        <div class="row">
                                            <div class="form-group form-horizontal">
                                                <div class="col-md-3">
                                                    <label class="control-label" for="cp"><?php echo _("Certificate Policies") ?></label>
                                                    <i class="fa fa-question-circle fpbx-help-icon" data-for="cp"></i>
                                                </div>
                                                <div class="col-md-9">
                                                    <textarea class="form-control" rows=3 readonly><?php echo $certinfo['extensions']['certificatePolicies'] ?></textarea>
                                                </div>
                                            </div>
                                            <div class="col-md-12">
                                                <span id="cp-help" class="help-block fpbx-help-block" style=""><?php echo _('A certificate policy (CP) is a document which aims to state what are the different actors of a public key infrastructure (PKI), their roles and their duties') ?></span>
                                            </div>
                                        </div>
                                    </div>
                                    <!-- END Policies -->
                                </div>
                            <?php } ?>
                            <!-- END Section -->
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script type="text/javascript">
    document.getElementById('challengetype').addEventListener('change', function () {
        var challengetype = this.value;
        if (challengetype === 'dns') {
            document.getElementById('dns-provider-container').style.display = 'block';
            document.getElementById('dns-credentials-container').style.display = 'block';
        } else {
            document.getElementById('dns-provider-container').style.display = 'none';
            document.getElementById('dns-credentials-container').style.display = 'none';
        }
    });

    // Trigger change event to set initial state
    document.getElementById('challengetype').dispatchEvent(new Event('change'));
</script>
