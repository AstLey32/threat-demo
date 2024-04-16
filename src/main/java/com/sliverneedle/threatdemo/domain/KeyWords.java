package com.sliverneedle.threatdemo.domain;

import java.io.Serializable;

/**
 * 
 * @TableName key_words
 */
public class KeyWords implements Serializable {
    /**
     * 
     */
    private Long id;

    /**
     * 
     */
    private String keywords;

    /**
     * 
     */
    private Integer points;

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
    public String getKeywords() {
        return keywords;
    }

    /**
     * 
     */
    public void setKeywords(String keywords) {
        this.keywords = keywords;
    }

    /**
     * 
     */
    public Integer getPoints() {
        return points;
    }

    /**
     * 
     */
    public void setPoints(Integer points) {
        this.points = points;
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
        KeyWords other = (KeyWords) that;
        return (this.getId() == null ? other.getId() == null : this.getId().equals(other.getId()))
            && (this.getKeywords() == null ? other.getKeywords() == null : this.getKeywords().equals(other.getKeywords()))
            && (this.getPoints() == null ? other.getPoints() == null : this.getPoints().equals(other.getPoints()));
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getId() == null) ? 0 : getId().hashCode());
        result = prime * result + ((getKeywords() == null) ? 0 : getKeywords().hashCode());
        result = prime * result + ((getPoints() == null) ? 0 : getPoints().hashCode());
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName());
        sb.append(" [");
        sb.append("Hash = ").append(hashCode());
        sb.append(", id=").append(id);
        sb.append(", keywords=").append(keywords);
        sb.append(", points=").append(points);
        sb.append(", serialVersionUID=").append(serialVersionUID);
        sb.append("]");
        return sb.toString();
    }
}