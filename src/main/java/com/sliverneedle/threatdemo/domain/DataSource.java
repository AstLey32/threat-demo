package com.sliverneedle.threatdemo.domain;

import java.io.Serializable;

/**
 * 
 * @TableName data_source
 */
public class DataSource implements Serializable {
    /**
     * 
     */
    private Long id;

    /**
     * 
     */
    private String url;

    /**
     * 
     */
    private String rule;

    /**
     * 
     */
    private String poster;

    /**
     * 
     */
    private String category;

    /**
     * 
     */
    private Boolean valid;

    private static final long serialVersionUID = 1L;

    /**
     * 
     */
    public Long getId() {
        return id;
    }

    /**
     * 
     */
    public void setId(Long id) {
        this.id = id;
    }

    /**
     * 
     */
    public String getUrl() {
        return url;
    }

    /**
     * 
     */
    public void setUrl(String url) {
        this.url = url;
    }

    /**
     * 
     */
    public String getRule() {
        return rule;
    }

    /**
     * 
     */
    public void setRule(String rule) {
        this.rule = rule;
    }

    /**
     * 
     */
    public String getPoster() {
        return poster;
    }

    /**
     * 
     */
    public void setPoster(String poster) {
        this.poster = poster;
    }

    /**
     * 
     */
    public String getCategory() {
        return category;
    }

    /**
     * 
     */
    public void setCategory(String category) {
        this.category = category;
    }

    /**
     * 
     */
    public Boolean getValid() {
        return valid;
    }

    /**
     * 
     */
    public void setValid(Boolean valid) {
        this.valid = valid;
    }

    @Override
    public boolean equals(Object that) {
        if (this == that) {
            return true;
        }
        if (that == null) {
            return false;
        }
        if (getClass() != that.getClass()) {
            return false;
        }
        DataSource other = (DataSource) that;
        return (this.getId() == null ? other.getId() == null : this.getId().equals(other.getId()))
            && (this.getUrl() == null ? other.getUrl() == null : this.getUrl().equals(other.getUrl()))
            && (this.getRule() == null ? other.getRule() == null : this.getRule().equals(other.getRule()))
            && (this.getPoster() == null ? other.getPoster() == null : this.getPoster().equals(other.getPoster()))
            && (this.getCategory() == null ? other.getCategory() == null : this.getCategory().equals(other.getCategory()))
            && (this.getValid() == null ? other.getValid() == null : this.getValid().equals(other.getValid()));
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getId() == null) ? 0 : getId().hashCode());
        result = prime * result + ((getUrl() == null) ? 0 : getUrl().hashCode());
        result = prime * result + ((getRule() == null) ? 0 : getRule().hashCode());
        result = prime * result + ((getPoster() == null) ? 0 : getPoster().hashCode());
        result = prime * result + ((getCategory() == null) ? 0 : getCategory().hashCode());
        result = prime * result + ((getValid() == null) ? 0 : getValid().hashCode());
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName());
        sb.append(" [");
        sb.append("Hash = ").append(hashCode());
        sb.append(", id=").append(id);
        sb.append(", url=").append(url);
        sb.append(", rule=").append(rule);
        sb.append(", poster=").append(poster);
        sb.append(", category=").append(category);
        sb.append(", valid=").append(valid);
        sb.append(", serialVersionUID=").append(serialVersionUID);
        sb.append("]");
        return sb.toString();
    }
}