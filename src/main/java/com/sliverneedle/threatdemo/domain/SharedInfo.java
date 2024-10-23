package com.sliverneedle.threatdemo.domain;

import java.io.Serializable;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * 
 * @TableName shared_info
 */
public class SharedInfo implements Serializable {
    /**
     * 
     */
    private Long id;

    /**
     * 
     */
    private String name;

    /**
     * 
     */
    private String description;

    /**
     * 
     */
    private String external_references;

    /**
     * 
     */
    private String labels;

    /**
     * 
     */
    private String type;

    /**
     * 
     */
    private Date created;

    /**
     * 
     */
    private Date created_by_ref;

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
    public String getName() {
        return name;
    }

    /**
     * 
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * 
     */
    public String getDescription() {
        return description;
    }

    /**
     * 
     */
    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * 
     */
    public String getExternalReferences() {
        return external_references;
    }

    /**
     * 
     */
    public void setExternalReferences(String external_references) {
        this.external_references = external_references;
    }

    /**
     * 
     */
    public String getLabels() {
        return labels;
    }

    /**
     * 
     */
    public void setLabels(String labels) {
        this.labels = labels;
    }

    /**
     * 
     */
    public String getType() {
        return type;
    }

    /**
     * 
     */
    public void setType(String type) {
        this.type = type;
    }

    /**
     * 
     */
    public Date getCreated() {
        return created;
    }

    /**
     * 
     */
    public void setCreated(Date created) {
        this.created = created;
    }

    /**
     * 
     */
    public Date getCreatedByRef() {
        return created_by_ref;
    }

    /**
     * 
     */
    public void setCreatedByRef(Date created_by_ref) {
        this.created_by_ref = created_by_ref;
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
        SharedInfo other = (SharedInfo) that;
        return (this.getId() == null ? other.getId() == null : this.getId().equals(other.getId()))
            && (this.getName() == null ? other.getName() == null : this.getName().equals(other.getName()))
            && (this.getDescription() == null ? other.getDescription() == null : this.getDescription().equals(other.getDescription()))
            && (this.getExternalReferences() == null ? other.getExternalReferences() == null : this.getExternalReferences().equals(other.getExternalReferences()))
            && (this.getLabels() == null ? other.getLabels() == null : this.getLabels().equals(other.getLabels()))
            && (this.getType() == null ? other.getType() == null : this.getType().equals(other.getType()))
            && (this.getCreated() == null ? other.getCreated() == null : this.getCreated().equals(other.getCreated()))
            && (this.getCreatedByRef() == null ? other.getCreatedByRef() == null : this.getCreatedByRef().equals(other.getCreatedByRef()));
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getId() == null) ? 0 : getId().hashCode());
        result = prime * result + ((getName() == null) ? 0 : getName().hashCode());
        result = prime * result + ((getDescription() == null) ? 0 : getDescription().hashCode());
        result = prime * result + ((getExternalReferences() == null) ? 0 : getExternalReferences().hashCode());
        result = prime * result + ((getLabels() == null) ? 0 : getLabels().hashCode());
        result = prime * result + ((getType() == null) ? 0 : getType().hashCode());
        result = prime * result + ((getCreated() == null) ? 0 : getCreated().hashCode());
        result = prime * result + ((getCreatedByRef() == null) ? 0 : getCreatedByRef().hashCode());
        return result;
    }

    @Override
    public String toString() {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"id\": ").append(id);
        sb.append(", \"name\": \"").append(name);
        sb.append("\", \"description\": \"").append(description);
        sb.append("\", \"external_references\": \"").append(external_references);
        sb.append("\", \"labels\": \"").append(labels);
        sb.append("\", \"type\": \"").append(type);
        if (created != null) {
            sb.append("\", \"created\": \"").append(sdf.format(created));
        } else {
            sb.append("\", \"created\": null");
        }
        if (created_by_ref != null) {
            sb.append("\", \"created_by_ref\": \"").append(sdf.format(created_by_ref));
            sb.append("\"}");
        } else {
            sb.append("\", \"created_by_ref\": null}");
        }
        return sb.toString();
    }
}