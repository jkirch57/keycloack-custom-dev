<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true; section>
    <#if section = "header">
        ${msg("doLogIn")}
    <#elseif section = "form">
        <div id="kc-form">
            <div id="kc-form-wrapper">
                <form id="kc-form-login" onsubmit="login.disabled = true; return true;" action="${url.loginAction}"
                      method="post">
                    <div class="${properties.kcFormGroupClass!}">
                        <label for="username" class="${properties.kcLabelClass!}">${msg("username")}</label>
                        <input tabindex="1" id="username" class="${properties.kcInputClass!}" name="username"
                               value="${(login.username!'')}" type="text" autofocus autocomplete="off"/>
                    </div>

                    <div class="${properties.kcFormGroupClass!}">
                        <label for="password" class="${properties.kcLabelClass!}">${msg("password")}</label>
                        <input tabindex="2" id="password" class="${properties.kcInputClass!}" name="password"
                               type="password" autocomplete="off"/>
                    </div>

                    <div class="${properties.kcFormGroupClass!}">
                        <label for="tokentype" class="${properties.kcLabelClass!}">${msg("tokentype")}</label>
                        <select tabindex="3" id="tokentype" class="${properties.kcInputClass!}" name="tokentype" onchange="togglePasscode(this);">
                            <option value="push" <#if !(radius??) || radius == "push"> selected </#if>>
                                ${msg("tokentypePush")}
                            </option>
                            <option value="code" <#if (radius??) && radius == "code"> selected </#if>>
                                ${msg("tokentypeCode")}
                            </option>
                        </select>
                    </div>

                    <div id="passcodeDiv" class="${properties.kcFormGroupClass!}" <#if !(radius??) || radius == "push"> style="display: none;" </#if>>
                        <label for="passcode" class="${properties.kcLabelClass!}">${msg("passcode")}</label>
                        <input tabindex="4" id="passcode" class="${properties.kcInputClass!}" name="passcode"
                               type="password" />
                    </div>

                    <div class="${properties.kcFormGroupClass!} ${properties.kcFormSettingClass!}">
                        <div id="kc-form-options">
                            <#if realm.rememberMe>
                                <div class="checkbox">
                                    <label>
                                        <#if login.rememberMe??>
                                            <input tabindex="5" id="rememberMe" name="rememberMe" type="checkbox"
                                                   checked> ${msg("rememberMe")}
                                        <#else>
                                            <input tabindex="5" id="rememberMe" name="rememberMe"
                                                   type="checkbox"> ${msg("rememberMe")}
                                        </#if>
                                    </label>
                                </div>
                            </#if>
                        </div>
                        <div class="${properties.kcFormOptionsWrapperClass!}">
                            <#if realm.resetPasswordAllowed>
                                <span><a tabindex="6"
                                         href="${url.loginResetCredentialsUrl}">${msg("doForgotPassword")}</a></span>
                            </#if>
                        </div>
                    </div>

                    <div id="kc-form-buttons" class="${properties.kcFormGroupClass!}">
                        <input tabindex="7"
                               class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                               name="login" id="kc-login" type="submit" value="${msg("doLogIn")}"/>
                    </div>
                </form>
            </div>
        </div>
    </#if>

    <script>
        function togglePasscode(select) {
            if (select.value == "code") {
                document.getElementById("passcodeDiv").style.display = "block";
            } else {
                document.getElementById("passcodeDiv").style.display = "none";
            }
        }
    </script>
</@layout.registrationLayout>