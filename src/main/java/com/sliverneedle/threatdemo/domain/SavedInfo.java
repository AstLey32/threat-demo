package com.sliverneedle.threatdemo.domain;

import java.io.Serializable;
import java.util.Date;

/**
 * 
 * @TableName saved_info
 */
public class SavedInfo implements Serializable {
    /**
     * 
     */
    private Long id;

    /**
     * 
     */
    private String title;

    /**
     * 
     */
    private String link;

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
    private String mark;

    /**
     * 
     */
    private Date savetime;

    /**
     * 
     */
    private String titlecn;

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
    public String getTitle() {
        return title;
    }

    /**
     * 
     */
    public void setTitle(String title) {
        this.title = title;
    }

    /**
     * 
     */
    public String getLink() {
        return link;
    }

    /**
     * 
     */
    public void setLink(String link) {
        this.link = link;
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
    public String getMark() {
        return mark;
    }

    /**
     * 
     */
    public void setMark(String mark) {
        this.mark = mark;
    }

    /**
     * 
     */
    public Date getSavetime() {
        return savetime;
    }

    /**
     * 
     */
    public void setSavetime(Date savetime) {
        this.savetime = savetime;
    }

    /**
     * 
     */
    public String getTitlecn() {
        return titlecn;
    }

    /**
     * 
     */
    public void setTitlecn(String titlecn) {
        this.titlecn = titlecn;
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
        SavedInfo other = (SavedInfo) that;
        return (this.getId() == null ? other.getId() == null : this.getId().equals(other.getId()))
            && (this.getTitle() == null ? other.getTitle() == null : this.getTitle().equals(other.getTitle()))
            && (this.getLink() == null ? other.getLink() == null : this.getLink().equals(other.getLink()))
            && (this.getPoster() == null ? other.getPoster() == null : this.getPoster().equals(other.getPoster()))
            && (this.getCategory() == null ? other.getCategory() == null : this.getCategory().equals(other.getCategory()))
            && (this.getMark() == null ? other.getMark() == null : this.getMark().equals(other.getMark()))
            && (this.getSavetime() == null ? other.getSavetime() == null : this.getSavetime().equals(other.getSavetime()))
            && (this.getTitlecn() == null ? other.getTitlecn() == null : this.getTitlecn().equals(other.getTitlecn()));
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getId() == null) ? 0 : getId().hashCode());
        result = prime * result + ((getTitle() == null) ? 0 : getTitle().hashCode());
        result = prime * result + ((getLink() == null) ? 0 : getLink().hashCode());
        result = prime * result + ((getPoster() == null) ? 0 : getPoster().hashCode());
        result = prime * result + ((getCategory() == null) ? 0 : getCategory().hashCode());
        result = prime * result + ((getMark() == null) ? 0 : getMark().hashCode());
        result = prime * result + ((getSavetime() == null) ? 0 : getSavetime().hashCode());
        result = prime * result + ((getTitlecn() == null) ? 0 : getTitlecn().hashCode());
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName());
        sb.append(" [");
        sb.append("Hash = ").append(hashCode());
        sb.append(", id=").append(id);
        sb.append(", title=").append(title);
        sb.append(", link=").append(link);
        sb.append(", poster=").append(poster);
        sb.append(", category=").append(category);
        sb.append(", mark=").append(mark);
        sb.append(", savetime=").append(savetime);
        sb.append(", titlecn=").append(titlecn);
        sb.append(", serialVersionUID=").append(serialVersionUID);
        sb.append("]");
        return sb.toString();
    }
}