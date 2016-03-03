package com.dogjaw.services.authentication.b2c;

import com.fasterxml.jackson.annotation.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;

/**
 * Created by Keith Hoopes on 3/2/2016.
 * <p/>
 * For holding OAuth2 claims retrieved from the content of a JWT.
 * Possibly for transforming into UserDetails, instead of
 * accessing the GraphAPI.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class UserClaims implements UserDetails {

    @JsonProperty("sub")
    private String sub;

    @JsonProperty("nbf")
    private Date nbf;

    @JsonProperty("iss")
    private String iss;

    @JsonProperty("emails")
    private List<String> emails;

    @JsonProperty("ver")
    private String ver;

    @JsonProperty("given_name")
    private String givenName;

    @JsonProperty("iat")
    private String iat;

    @JsonProperty("auth_time")
    private Date auth_time;

    @JsonProperty("user_name")
    private String user_name;

    @JsonProperty("exp")
    private Date exp;

    @JsonProperty("oid")
    private String oid;

    @JsonProperty("name")
    private String name;

    @JsonProperty("aud")
    private String aud;

    @JsonProperty("family_name")
    private String family_name;

    @JsonProperty("acr")
    private String acr;

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public Date getNbf() {
        return nbf;
    }

    public void setNbf(Date nbf) {
        this.nbf = nbf;
    }

    public String getIss() {
        return iss;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public List<String> getEmails() {
        return emails;
    }

    public void setEmails(List<String> emails) {
        this.emails = emails;
    }

    public String getVer() {
        return ver;
    }

    public void setVer(String ver) {
        this.ver = ver;
    }

    public String getGivenName() {
        return givenName;
    }

    public void setGivenName(String givenName) {
        this.givenName = givenName;
    }

    public String getIat() {
        return iat;
    }

    public void setIat(String iat) {
        this.iat = iat;
    }

    public Date getAuthTime() {
        return auth_time;
    }

    public void setAuthTime(Date auth_time) {
        this.auth_time = auth_time;
    }

    public Date getExp() {
        return exp;
    }

    public void setExp(Date exp) {
        this.exp = exp;
    }

    public String getOid() {
        return oid;
    }

    public void setOid(String oid) {
        this.oid = oid;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getAud() {
        return aud;
    }

    public void setAud(String aud) {
        this.aud = aud;
    }

    public String getFamilyName() {
        return family_name;
    }

    public void setFamilyName(String family_name) {
        this.family_name = family_name;
    }

    public String getAcr() {
        return acr;
    }

    public void setAcr(String acr) {
        this.acr = acr;
    }

    @Override
    public String toString() {
        return "ClassPojo [sub = " + sub + ", nbf = " + nbf + ", iss = " + iss + ", emails = " + emails + ", ver = " + ver + ", given_name = " + givenName + ", iat = " + iat + ", auth_time = " + auth_time + ", user_name = " + user_name + ", exp = " + exp + ", oid = " + oid + ", name = " + name + ", aud = " + aud + ", family_name = " + family_name + ", acr = " + acr + "]";
    }


    @JsonIgnore
    private Map<String, Object> additionalProperties;

    @JsonAnyGetter
    public Map<String, Object> getAdditionalProperties() {
        return this.additionalProperties;
    }

    @JsonAnySetter
    public void setAdditionalProperty(String name, Object value) {
        this.additionalProperties.put(name, value);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_CUSTOMER");
        return Collections.singletonList(authority);
    }

    @Override
    public String getPassword() {

        return "noop_password";
    }

    @Override
    public String getUsername() {

        return user_name;
    }

    @Override
    public boolean isAccountNonExpired() {

        return isCredentialsNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {

        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {

        return exp != null && exp.getTime() < System.currentTimeMillis();
    }

    @Override
    public boolean isEnabled() {

        return isCredentialsNonExpired();
    }
}
